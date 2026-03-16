use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::config::DEFAULT_PORT;
use crate::peers::KnownPeers;
use crate::transfer::sender::{run_sender, SenderOptions};

#[derive(Debug, clap::Args)]
#[command(
    about = "파일/폴더를 상대방에게 전송",
    long_about = "\
파일 또는 폴더를 지정한 피어에게 전송합니다.

【처음 연결할 때】
  수신자가 출력한 주소와 인증 코드를 함께 입력합니다.
  $ ftransfer send --to 203.0.113.45:55000 --code a8f3-k2m9 --path ./photos

【재연결할 때】
  한 번 연결된 피어는 known_peers.yaml에 저장됩니다.
  코드 없이 자동으로 연결됩니다.

  # 가장 최근 피어에 자동 연결
  $ ftransfer send --path ./photos

  # 특정 피어 선택 (--list로 번호 확인)
  $ ftransfer send --index 2 --path ./photos

【연결 이력 보기】
  $ ftransfer send --list
",
    after_help = "피어 정보는 ~/.ftransfer/known_peers.yaml에 저장됩니다.",
)]
pub struct SendArgs {
    /// 대상 주소 (예: 203.0.113.45:55000) — 처음 연결 시 필요
    #[arg(long, value_name = "IP:PORT")]
    pub to: Option<String>,

    /// 인증 코드 — 처음 연결 시 필요 (수신자 화면에 표시됨)
    #[arg(long, value_name = "CODE")]
    pub code: Option<String>,

    /// known_peers 목록에서 번호로 피어 선택 (1-based)
    #[arg(long, value_name = "N")]
    pub index: Option<usize>,

    /// index 피어에 별칭 설정
    #[arg(long, value_name = "ALIAS")]
    pub alias: Option<String>,

    /// 전송할 파일 또는 폴더 경로
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// 최근 연결 이력 표시
    #[arg(long, default_value_t = false)]
    pub list: bool,

    /// 피어 수동 추가 (예: 203.0.113.45:9999)
    #[arg(long, value_name = "IP:PORT")]
    pub add: Option<String>,

    /// index 피어 삭제
    #[arg(long, value_name = "N")]
    pub remove: Option<usize>,
}

pub async fn handle_send(args: SendArgs) -> Result<()> {

    // --list: 이력 조회 후 종료
    if args.list {
        let peers = KnownPeers::load()?;
        peers.print_send_list();
        return Ok(());
    }

    // --add: 피어 수동 추가
    if let Some(addr) = &args.add {
        let (ip, port) = parse_addr(addr)?;
        let mut peers = KnownPeers::load()?;

        // 중복 확인
        if peers.find_send_peer(&ip).is_some() {
            anyhow::bail!("peer {} already exists. Use --index N --alias to edit.", ip);
        }

        let now = chrono::Utc::now();
        peers.send_peers.push(crate::peers::store::PeerEntry {
            ip: ip.clone(),
            port,
            public_key: String::new(), // 첫 연결 시 채워짐
            alias: args.alias.clone(),
            first_seen: now,
            last_seen: now,
            transfer_count: 0,
        });
        peers.save()?;

        let alias_str = args.alias.as_deref().unwrap_or("-");
        println!("[✓] Added: {}:{} (alias: {})", ip, port, alias_str);
        return Ok(());
    }

    // --remove: 피어 삭제
    if let Some(idx) = args.remove {
        let mut peers = KnownPeers::load()?;
        anyhow::ensure!(
            idx >= 1 && idx <= peers.send_peers.len(),
            "no peer at index {}",
            idx
        );
        let removed = peers.send_peers.remove(idx - 1);
        peers.save()?;
        println!(
            "[✓] Removed: index {} ({}:{})",
            idx, removed.ip, removed.port
        );
        return Ok(());
    }

    // --index + --alias: 별칭 설정
    if let (Some(idx), Some(alias)) = (args.index, args.alias.clone()) {
        let mut peers = KnownPeers::load()?;
        let peer = peers
            .send_peers
            .get_mut(idx - 1)
            .with_context(|| format!("no peer at index {}", idx))?;
        peer.alias = Some(alias.clone());
        peers.save()?;
        println!("[✓] Alias set: index {} → \"{}\"", idx, alias);
        return Ok(());
    }

    // --path 필수 확인
    println!("upnp v{}", env!("CARGO_PKG_VERSION"));
    println!();
    let path = args.path.clone().context("--path is required")?;
    anyhow::ensure!(path.exists(), "path does not exist: {}", path.display());

    // 연결 대상 결정
    let (target_ip, target_port) = resolve_target(&args)?;

    run_sender(SenderOptions {
        target_ip,
        target_port,
        path,
        auth_code: args.code,
    })
    .await
}

/// 연결 대상 IP:PORT 결정
/// 우선순위: --to > --index > 자동(최근 peer)
fn resolve_target(args: &SendArgs) -> Result<(String, u16)> {
    // 1. --to 명시
    if let Some(to) = &args.to {
        return parse_addr(to);
    }

    let peers = KnownPeers::load()?;

    // 2. --index 지정
    if let Some(idx) = args.index {
        let peer = peers
            .send_peer_by_index(idx)
            .with_context(|| format!("no peer at index {}", idx))?;
        println!("[→] Connecting to index {}: {}:{}", idx, peer.ip, peer.port);
        return Ok((peer.ip.clone(), peer.port));
    }

    // 3. 자동: 최근 peer
    if let Some(peer) = peers.latest_send_peer() {
        let display = peer
            .alias
            .as_deref()
            .map(|a| format!("{} ({})", peer.ip, a))
            .unwrap_or_else(|| peer.ip.clone());
        println!(
            "[→] Auto-connecting to last peer: {}:{}  {}",
            peer.ip, peer.port, display
        );
        return Ok((peer.ip.clone(), peer.port));
    }

    anyhow::bail!("no known peers. Use --to <IP:PORT> --code <CODE> for first connection")
}

fn parse_addr(addr: &str) -> Result<(String, u16)> {
    if let Some((ip, port_str)) = addr.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid port: {}", port_str))?;
        Ok((ip.to_string(), port))
    } else {
        // 포트 없으면 기본값 사용
        Ok((addr.to_string(), DEFAULT_PORT))
    }
}
