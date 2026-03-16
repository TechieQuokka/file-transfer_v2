use anyhow::{Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::auth::identity::Identity;
use crate::net::tls::make_client_config;
use crate::peers::store::{KnownPeers, PeerEntry};
use crate::protocol::{
    AuthRequest, AuthResponse, ChunkAck, ChunkHeader, HandshakeInit, HandshakeResponse,
    ResumeInfo, TransferComplete, MSG_AUTH_REQUEST, MSG_AUTH_RESPONSE, MSG_CHUNK, MSG_CHUNK_ACK,
    MSG_HANDSHAKE_INIT, MSG_HANDSHAKE_RESPONSE, MSG_MANIFEST, MSG_RESUME_INFO,
    MSG_TRANSFER_COMPLETE,
};
use crate::transfer::chunk::{chunk_size_for, scan_path, TransferManifest};

pub struct SenderOptions {
    pub target_ip: String,
    pub target_port: u16,
    pub path: std::path::PathBuf,
    pub auth_code: Option<String>,
}

pub async fn run_sender(opts: SenderOptions) -> Result<()> {
    let identity = Identity::load_or_create()?;
    let mut peers = KnownPeers::load()?;

    let addr = format!("{}:{}", opts.target_ip, opts.target_port);
    println!("[→] Connecting to {}...", addr);

    let stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("failed to connect to {}", addr))?;

    let client_config = make_client_config()?;
    let connector = TlsConnector::from(client_config);

    let server_name = rustls::pki_types::ServerName::DnsName(
        rustls::pki_types::DnsName::try_from("ftransfer".to_string())
            .map_err(|e| anyhow::anyhow!("invalid server name: {}", e))?,
    );

    let mut tls = connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake failed")?;

    println!("[✓] TLS connected");

    let is_known = peers.find_send_peer(&opts.target_ip).is_some();
    let peer_pubkey = peers.find_send_peer(&opts.target_ip).map(|p| p.public_key.clone());

    let handshake = HandshakeInit {
        sender_public_key: identity.public_key_b64.clone(),
        is_known_peer: is_known,
    };
    write_message(&mut tls, MSG_HANDSHAKE_INIT, &handshake).await?;

    let resp: HandshakeResponse = read_message(&mut tls, MSG_HANDSHAKE_RESPONSE).await?;

    if let Some(known_key) = &peer_pubkey {
        if known_key != &resp.receiver_public_key {
            eprintln!();
            eprintln!("WARNING: Remote host identification has changed!");
            eprintln!("IP {}의 공개키가 known_peers.yaml과 다릅니다.", opts.target_ip);
            eprintln!("중간자 공격(MITM)일 수 있습니다.");
            eprintln!("계속하려면 known_peers.yaml에서 해당 항목을 삭제하세요.");
            eprintln!();
            anyhow::bail!("public key mismatch — aborting");
        }
        println!("[✓] Known peer verified");
    } else {
        let code = opts.auth_code.as_deref().context("first connection requires --code")?;
        let auth_req = AuthRequest { code: code.to_string() };
        write_message(&mut tls, MSG_AUTH_REQUEST, &auth_req).await?;

        let auth_resp: AuthResponse = read_message(&mut tls, MSG_AUTH_RESPONSE).await?;
        if !auth_resp.accepted {
            anyhow::bail!("authentication failed — wrong code");
        }
        println!("[✓] Authenticated");
    }

    println!("[→] Scanning files...");
    let entries = scan_path(&opts.path).await?;
    let total_size: u64 = entries.iter().map(|e| e.size).sum();
    let total_files = entries.len();

    let manifest = TransferManifest { files: entries.clone(), total_size, total_files };
    println!("[→] Sending: {} ({} files, {})", opts.path.display(), total_files, human_size(total_size));

    write_message(&mut tls, MSG_MANIFEST, &manifest).await?;

    // Receiver로부터 resume 정보 수신
    let resume_info: ResumeInfo = read_message(&mut tls, MSG_RESUME_INFO).await?;
    let resumed_count: usize = resume_info.files.iter().map(|(_, v)| v.len()).sum();
    if resumed_count > 0 {
        println!("[→] Resuming: {} chunks already received", resumed_count);
    }

    let mp = MultiProgress::new();
    let total_bar = mp.add(ProgressBar::new(total_size));
    total_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes}  {bytes_per_sec}")
            .unwrap()
            .progress_chars("█░"),
    );

    for entry in &entries {
        // 이 파일에 대해 이미 받은 청크 목록 조회
        let received_chunks: Vec<u64> = resume_info
            .files
            .iter()
            .find(|(path, _)| path == &entry.relative_path)
            .map(|(_, chunks)| chunks.clone())
            .unwrap_or_default();

        // 이미 받은 청크 크기만큼 progress bar 미리 진행
        let already_bytes: u64 = received_chunks
            .iter()
            .map(|&idx| chunk_size_for(entry.size, idx) as u64)
            .sum();
        total_bar.inc(already_bytes);

        let file_bar = mp.add(ProgressBar::new(entry.size));
        file_bar.set_style(
            ProgressStyle::default_bar()
                .template("  {msg:<40} [{bar:30}] {bytes}/{total_bytes}")
                .unwrap()
                .progress_chars("█░"),
        );
        file_bar.set_message(entry.relative_path.clone());
        file_bar.inc(already_bytes);

        send_file(&mut tls, &opts.path, entry, &received_chunks, &file_bar, &total_bar).await?;
        file_bar.finish_and_clear();
    }

    write_message(&mut tls, MSG_TRANSFER_COMPLETE, &TransferComplete { success: true }).await?;
    total_bar.finish_with_message("Done");
    println!("[✓] Transfer complete ({} files, {})", total_files, human_size(total_size));

    let now = chrono::Utc::now();
    let entry = PeerEntry {
        ip: opts.target_ip.clone(),
        port: opts.target_port,
        public_key: resp.receiver_public_key,
        alias: None,
        first_seen: peers.find_send_peer(&opts.target_ip).map(|p| p.first_seen).unwrap_or(now),
        last_seen: now,
        transfer_count: peers
            .find_send_peer(&opts.target_ip)
            .map(|p| p.transfer_count + 1)
            .unwrap_or(1),
    };
    peers.upsert_send_peer(entry);
    peers.save()?;

    Ok(())
}

async fn send_file<S>(
    stream: &mut S,
    root: &Path,
    entry: &crate::transfer::chunk::FileEntry,
    received_chunks: &[u64],  // 이미 받은 청크 — 건너뜀
    file_bar: &ProgressBar,
    total_bar: &ProgressBar,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let file_path = if root.is_file() {
        root.to_path_buf()
    } else {
        root.parent()
            .unwrap_or(root)
            .join(&entry.relative_path)
    };
    let mut file = tokio::fs::File::open(&file_path)
        .await
        .with_context(|| format!("failed to open {}", file_path.display()))?;

    for chunk_idx in 0..entry.total_chunks {
        let size = chunk_size_for(entry.size, chunk_idx);

        // 이미 받은 청크는 파일 포인터만 이동하고 전송 건너뜀
        if received_chunks.contains(&chunk_idx) {
            let mut skip = vec![0u8; size];
            file.read_exact(&mut skip).await?;
            continue;
        }

        let mut chunk_data = vec![0u8; size];
        file.read_exact(&mut chunk_data).await
            .with_context(|| format!("failed to read chunk {} of {}", chunk_idx, entry.relative_path))?;

        write_message(stream, MSG_CHUNK, &ChunkHeader {
            relative_path: entry.relative_path.clone(),
            chunk_idx,
            total_chunks: entry.total_chunks,
            data_len: size as u32,
        }).await?;
        stream.write_all(&chunk_data).await?;
        stream.flush().await?;

        let _ack: ChunkAck = read_message(stream, MSG_CHUNK_ACK).await?;
        file_bar.inc(size as u64);
        total_bar.inc(size as u64);
    }
    Ok(())
}

async fn write_message<S, T>(stream: &mut S, msg_type: u8, payload: &T) -> Result<()>
where S: AsyncWriteExt + Unpin, T: serde::Serialize {
    let json = serde_json::to_vec(payload)?;
    let mut buf = Vec::with_capacity(1 + 4 + json.len());
    buf.push(msg_type);
    buf.extend_from_slice(&(json.len() as u32).to_be_bytes());
    buf.extend_from_slice(&json);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_message<S, T>(stream: &mut S, expected_type: u8) -> Result<T>
where S: AsyncReadExt + Unpin, T: serde::de::DeserializeOwned {
    let msg_type = stream.read_u8().await?;
    anyhow::ensure!(msg_type == expected_type, "unexpected message type: got {}, expected {}", msg_type, expected_type);
    let len = stream.read_u32().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 { format!("{:.1}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0)) }
    else if bytes >= 1024 * 1024 { format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0)) }
    else if bytes >= 1024 { format!("{:.1}KB", bytes as f64 / 1024.0) }
    else { format!("{}B", bytes) }
}