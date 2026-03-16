use anyhow::{Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::auth::code::AuthCode;
use crate::auth::identity::Identity;
use crate::net::tls::make_server_config;
use crate::net::upnp::{get_local_ips, open_upnp_port};
use crate::peers::store::{KnownPeers, PeerEntry};
use crate::protocol::{
    AuthRequest, AuthResponse, ChunkAck, ChunkHeader, HandshakeInit, HandshakeResponse,
    ResumeInfo, TransferComplete, MSG_AUTH_REQUEST, MSG_AUTH_RESPONSE, MSG_CHUNK, MSG_CHUNK_ACK,
    MSG_HANDSHAKE_INIT, MSG_HANDSHAKE_RESPONSE, MSG_MANIFEST, MSG_RESUME_INFO,
    MSG_TRANSFER_COMPLETE,
};
use crate::transfer::chunk::{ChunkState, TransferManifest};

pub struct ReceiverOptions {
    pub port: u16,
    pub output_dir: PathBuf,
    pub auto_accept: bool,
}

pub async fn run_receiver(opts: ReceiverOptions) -> Result<()> {
    let identity = Arc::new(Identity::load_or_create()?);

    let upnp_result = open_upnp_port(opts.port).await;
    let (upnp_ok, public_ip) = match &upnp_result {
        Ok(u) => (true, u.external_ip.clone()),
        Err(e) => {
            eprintln!("[✗] UPnP failed: {}", e);
            eprintln!("    → 라우터에서 UPnP를 활성화하거나 포트 {}를 수동으로 여세요.", opts.port);
            (false, None)
        }
    };

    if upnp_ok {
        println!("[✓] UPnP: port {} opened", opts.port);
    }

    let auth_code = Arc::new(AuthCode::generate());
    println!("Auth code: {}", auth_code);
    println!();

    println!("Available addresses:");
    for ip in &get_local_ips() {
        println!("  Local   {}:{}", ip, opts.port);
    }
    match &public_ip {
        Some(ip) => println!("  Public  {}:{}", ip, opts.port),
        None => println!("  Public  unknown (UPnP 실패)"),
    }
    println!();

    let listener = TcpListener::bind(format!("0.0.0.0:{}", opts.port))
        .await
        .with_context(|| format!("failed to bind port {}", opts.port))?;

    let server_config = make_server_config()?;
    let acceptor = TlsAcceptor::from(server_config);
    let opts = Arc::new(opts);

    println!("Waiting for connection...");

    tokio::select! {
        result = accept_loop(listener, acceptor, auth_code, identity, opts) => result,
        _ = tokio::signal::ctrl_c() => {
            println!("\n[→] Shutting down...");
            if let Ok(upnp) = upnp_result {
                if let Err(e) = upnp.close().await {
                    eprintln!("[✗] UPnP close failed: {}", e);
                } else {
                    println!("[✓] UPnP port closed");
                }
            }
            Ok(())
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    auth_code: Arc<AuthCode>,
    identity: Arc<Identity>,
    opts: Arc<ReceiverOptions>,
) -> Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let peer_ip = peer_addr.ip().to_string();

        println!("[→] Connection from {}", peer_addr);

        let tls_stream = match acceptor.accept(stream).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[✗] TLS error from {}: {}", peer_addr, e);
                continue;
            }
        };

        let auth_code = Arc::clone(&auth_code);
        let identity = Arc::clone(&identity);
        let opts = Arc::clone(&opts);

        tokio::spawn(async move {
            match handle_connection(tls_stream, peer_ip, &auth_code, &identity, &opts).await {
                Ok(_) => println!("\nWaiting for connection..."),
                Err(e) => {
                    eprintln!("[✗] Transfer error: {}", e);
                    println!("\nWaiting for connection...");
                }
            }
        });
    }
}

async fn handle_connection<S>(
    mut stream: S,
    peer_ip: String,
    auth_code: &AuthCode,
    identity: &Identity,
    opts: &ReceiverOptions,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut peers = KnownPeers::load()?;

    let init: HandshakeInit = read_message(&mut stream, MSG_HANDSHAKE_INIT).await?;
    let is_known = peers.find_recv_peer(&peer_ip).is_some();
    let stored_key = peers.find_recv_peer(&peer_ip).map(|p| p.public_key.clone());

    if is_known {
        if let Some(known_key) = &stored_key {
            if known_key != &init.sender_public_key {
                let resp = HandshakeResponse {
                    receiver_public_key: identity.public_key_b64.clone(),
                    accepted: false,
                    reason: Some("public key mismatch".to_string()),
                };
                write_message(&mut stream, MSG_HANDSHAKE_RESPONSE, &resp).await?;
                eprintln!();
                eprintln!("WARNING: Sender public key has changed!");
                eprintln!("IP {}의 공개키가 known_peers.yaml과 다릅니다.", peer_ip);
                eprintln!("중간자 공격(MITM)일 수 있습니다.");
                anyhow::bail!("public key mismatch from {}", peer_ip);
            }
        }
        let resp = HandshakeResponse {
            receiver_public_key: identity.public_key_b64.clone(),
            accepted: true,
            reason: None,
        };
        write_message(&mut stream, MSG_HANDSHAKE_RESPONSE, &resp).await?;
        println!("[✓] Known peer: {} — auto-authenticated", peer_ip);
    } else {
        let resp = HandshakeResponse {
            receiver_public_key: identity.public_key_b64.clone(),
            accepted: true,
            reason: None,
        };
        write_message(&mut stream, MSG_HANDSHAKE_RESPONSE, &resp).await?;

        let auth_req: AuthRequest = read_message(&mut stream, MSG_AUTH_REQUEST).await?;
        let ok = auth_code.verify(&auth_req.code);
        write_message(&mut stream, MSG_AUTH_RESPONSE, &AuthResponse { accepted: ok }).await?;

        if !ok {
            eprintln!("[✗] Wrong auth code from {}", peer_ip);
            anyhow::bail!("wrong auth code");
        }
        println!("[✓] Authenticated: {}", peer_ip);
    }

    let manifest: TransferManifest = read_message(&mut stream, MSG_MANIFEST).await?;
    println!("[→] Incoming: {} files, {}", manifest.total_files, human_size(manifest.total_size));

    if !opts.auto_accept {
        print!(
            "Accept transfer from {}? ({} files, {}) [y/n]: ",
            peer_ip, manifest.total_files, human_size(manifest.total_size)
        );
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" && input.trim().to_lowercase() != "yes" {
            println!("[✗] Transfer rejected");
            return Ok(());
        }
    }

    std::fs::create_dir_all(&opts.output_dir)?;

    // 파일별 resume 상태 수집 → ResumeInfo 전송
    // next_chunk()로 아직 받지 못한 청크가 있는지 확인
    // is_complete()로 이미 완료된 파일은 전체 청크를 received로 알려줌
    let resume_files: Vec<(String, Vec<u64>)> = manifest
        .files
        .iter()
        .map(|file_entry| {
            let state = ChunkState::load(&opts.output_dir, &file_entry.relative_path)
                .unwrap_or_else(|| ChunkState::new(file_entry));

            if state.is_complete() {
                // 완료된 파일 — 모든 청크 번호 전달
                let all_chunks: Vec<u64> = (0..file_entry.total_chunks).collect();
                (file_entry.relative_path.clone(), all_chunks)
            } else if state.next_chunk().is_some() {
                // 일부만 받은 파일 — 받은 청크 목록 전달
                (file_entry.relative_path.clone(), state.received_chunks.clone())
            } else {
                // 처음 받는 파일 — 빈 목록
                (file_entry.relative_path.clone(), vec![])
            }
        })
        .collect();

    let total_already: usize = resume_files.iter().map(|(_, v)| v.len()).sum();
    if total_already > 0 {
        println!("[→] Resume: {} chunks already received, skipping", total_already);
    }

    write_message(&mut stream, MSG_RESUME_INFO, &ResumeInfo { files: resume_files }).await?;

    let mp = MultiProgress::new();
    let total_bar = mp.add(ProgressBar::new(manifest.total_size));
    total_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes}  {bytes_per_sec}")
            .unwrap()
            .progress_chars("█░"),
    );

    let mut current_file: Option<(String, Vec<u8>, ChunkState, String)> = None;

    loop {
        let msg_type = stream.read_u8().await?;

        match msg_type {
            MSG_CHUNK => {
                let header: ChunkHeader = read_payload(&mut stream).await?;
                let mut chunk_data = vec![0u8; header.data_len as usize];
                stream.read_exact(&mut chunk_data).await?;

                let (_, buf, state, _) = match &mut current_file {
                    Some(cf) if cf.0 == header.relative_path => cf,
                    _ => {
                        if let Some((path, buf, state, expected_hash)) = current_file.take() {
                            flush_file(&opts.output_dir, &path, &buf, &state, &expected_hash).await?;
                        }

                        let file_entry = manifest
                            .files
                            .iter()
                            .find(|f| f.relative_path == header.relative_path)
                            .context("unknown file in chunk")?;

                        let state = ChunkState::load(&opts.output_dir, &header.relative_path)
                            .unwrap_or_else(|| ChunkState::new(file_entry));

                        let existing_data = load_partial(&opts.output_dir, &header.relative_path)
                            .unwrap_or_else(|| vec![0u8; file_entry.size as usize]);

                        current_file = Some((
                            header.relative_path.clone(),
                            existing_data,
                            state,
                            file_entry.blake3_hash.clone(),
                        ));
                        current_file.as_mut().unwrap()
                    }
                };

                if !state.is_chunk_received(header.chunk_idx) {
                    let offset = crate::transfer::chunk::chunk_offset(header.chunk_idx) as usize;
                    let end = (offset + chunk_data.len()).min(buf.len());
                    if offset < buf.len() {
                        buf[offset..end].copy_from_slice(&chunk_data[..end - offset]);
                    }
                    state.mark_received(header.chunk_idx);
                    state.save(&opts.output_dir)?;
                    total_bar.inc(chunk_data.len() as u64);
                }

                write_message(&mut stream, MSG_CHUNK_ACK, &ChunkAck {
                    chunk_idx: header.chunk_idx,
                    ok: true,
                }).await?;
            }

            MSG_TRANSFER_COMPLETE => {
                let _complete: TransferComplete = read_payload(&mut stream).await?;

                if let Some((path, buf, state, expected_hash)) = current_file.take() {
                    flush_file(&opts.output_dir, &path, &buf, &state, &expected_hash).await?;
                }

                total_bar.finish_with_message("Done");
                println!("[✓] Done. Saved to {}", opts.output_dir.display());
                break;
            }

            other => anyhow::bail!("unexpected message type: {}", other),
        }
    }

    let now = chrono::Utc::now();
    peers.upsert_recv_peer(PeerEntry {
        ip: peer_ip.clone(),
        port: 0,
        public_key: init.sender_public_key,
        alias: None,
        first_seen: peers.find_recv_peer(&peer_ip).map(|p| p.first_seen).unwrap_or(now),
        last_seen: now,
        transfer_count: peers
            .find_recv_peer(&peer_ip)
            .map(|p| p.transfer_count + 1)
            .unwrap_or(1),
    });
    peers.save()?;

    Ok(())
}

async fn flush_file(
    output_dir: &Path,
    relative_path: &str,
    data: &[u8],
    state: &ChunkState,
    expected_hash: &str,
) -> Result<()> {
    let actual_hash = blake3::hash(data).to_hex();
    anyhow::ensure!(
        actual_hash.as_str() == expected_hash,
        "integrity check failed for '{}': expected {}, got {}",
        relative_path, expected_hash, actual_hash
    );

    let out_path = output_dir.join(relative_path);
    if let Some(parent) = out_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&out_path, data).await?;
    state.delete(output_dir);
    Ok(())
}

fn load_partial(output_dir: &Path, relative_path: &str) -> Option<Vec<u8>> {
    std::fs::read(output_dir.join(relative_path)).ok()
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
    read_payload(stream).await
}

async fn read_payload<S, T>(stream: &mut S) -> Result<T>
where S: AsyncReadExt + Unpin, T: serde::de::DeserializeOwned {
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