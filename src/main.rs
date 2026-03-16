mod auth;
mod cli;
mod config;
mod net;
mod peers;
mod protocol;
mod transfer;

use anyhow::Result;
use clap::{Parser, Subcommand};

use cli::recv::RecvArgs;
use cli::send::SendArgs;
use cli::{handle_recv, handle_send};

#[derive(Debug, Parser)]
#[command(
    name = "upnp",
    version = env!("CARGO_PKG_VERSION"),
    about = "Pure P2P file transfer — no central server",
    long_about = "\
upnp — 중앙 서버 없는 순수 P2P 파일 전송 도구

인증된 피어는 known_peers.yaml에 저장되어
다음 연결부터 코드 없이 자동으로 연결됩니다.

예시:
  # 수신 대기 (기본 포트 55000, ~/Downloads 저장)
  upnp recv

  # 처음 전송 (코드 인증)
  upnp send --to 203.0.113.45:55000 --code a8f3-k2m9 --path ./photos

  # 이전 연결 목록 확인
  upnp send --list

  # 가장 최근 피어에 자동 연결
  upnp send --path ./photos
",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// 파일/폴더를 상대방에게 전송
    Send(SendArgs),
    /// 파일 수신 대기 (Ctrl+C로 종료)
    Recv(RecvArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    // ring을 TLS CryptoProvider로 명시 설치
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring crypto provider");

    let cli = Cli::parse();

    match cli.command {
        Commands::Send(args) => handle_send(args).await,
        Commands::Recv(args) => handle_recv(args).await,
    }
}