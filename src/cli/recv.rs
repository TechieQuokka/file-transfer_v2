use anyhow::Result;
use std::path::PathBuf;

use crate::config::{DEFAULT_PORT, default_download_dir};
use crate::transfer::receiver::{run_receiver, ReceiverOptions};

#[derive(Debug, clap::Args)]
#[command(
    about = "파일 수신 대기 (Ctrl+C로 종료)",
    long_about = "\
지정한 포트에서 수신 대기합니다.

시작하면 인증 코드와 접속 주소를 출력합니다.
이 정보를 송신자에게 전달하세요 (카톡, 이메일 등).

【기본 사용】
  $ ftransfer recv
  Auth code: a8f3-k2m9-x7q1
  Available addresses:
    Local   192.168.1.10:55000
    Public  203.0.113.45:55000

【저장 경로 지정】
  $ ftransfer recv --path ~/Desktop

【수동 승인 모드】
  $ ftransfer recv --pass false
  → 파일이 올 때마다 y/n으로 승인

수신 완료 후에도 계속 대기합니다. Ctrl+C로 종료하세요.
",
    after_help = "받은 파일은 기본적으로 ~/Downloads에 저장됩니다.",
)]
pub struct RecvArgs {
    /// 수신 대기 포트 [기본값: 55000]
    #[arg(long, value_name = "PORT", default_value_t = DEFAULT_PORT)]
    pub port: u16,

    /// 파일 저장 경로 [기본값: ~/Downloads]
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// 수동 승인 모드 (지정하면 y/n으로 승인)
    #[arg(long, default_value_t = false)]
    pub manual: bool,
}

pub async fn handle_recv(args: RecvArgs) -> Result<()> {
    let output_dir = args.path.unwrap_or_else(default_download_dir);

    println!("upnp v{}", env!("CARGO_PKG_VERSION"));
    println!();

    run_receiver(ReceiverOptions {
        port: args.port,
        output_dir,
        auto_accept: !args.manual,
    })
    .await
}
