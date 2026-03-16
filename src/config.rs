use std::path::PathBuf;

pub const DEFAULT_PORT: u16 = 55000;
pub const CHUNK_SIZE: usize = 256 * 1024; // 256KB
pub const APP_DIR_NAME: &str = ".upnp";
pub const KNOWN_PEERS_FILE: &str = "known_peers.yaml";
pub const IDENTITY_DIR: &str = "identity";
pub const PRIVATE_KEY_FILE: &str = "private.key";
pub const PUBLIC_KEY_FILE: &str = "public.key";
pub const RESUME_EXT: &str = ".ftresume";

pub fn app_dir() -> PathBuf {
    // 실행파일 위치 기준
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR_NAME)
}

pub fn known_peers_path() -> PathBuf {
    app_dir().join(KNOWN_PEERS_FILE)
}

pub fn identity_dir() -> PathBuf {
    app_dir().join(IDENTITY_DIR)
}

pub fn default_download_dir() -> PathBuf {
    dirs::download_dir().unwrap_or_else(|| PathBuf::from("."))
}