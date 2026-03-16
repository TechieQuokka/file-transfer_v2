use serde::{Deserialize, Serialize};

pub const MSG_HANDSHAKE_INIT: u8 = 0x01;
pub const MSG_HANDSHAKE_RESPONSE: u8 = 0x02;
pub const MSG_AUTH_REQUEST: u8 = 0x03;
pub const MSG_AUTH_RESPONSE: u8 = 0x04;
pub const MSG_MANIFEST: u8 = 0x05;
pub const MSG_CHUNK: u8 = 0x06;
pub const MSG_CHUNK_ACK: u8 = 0x07;
pub const MSG_TRANSFER_COMPLETE: u8 = 0x08;
pub const MSG_RESUME_INFO: u8 = 0x09;  // 추가

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub sender_public_key: String,
    pub is_known_peer: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub receiver_public_key: String,
    pub accepted: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub accepted: bool,
}

/// Receiver → Sender: 파일별 이미 받은 청크 목록
#[derive(Debug, Serialize, Deserialize)]
pub struct ResumeInfo {
    /// 파일별 (relative_path, 이미 받은 청크 번호 목록)
    pub files: Vec<(String, Vec<u64>)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChunkHeader {
    pub relative_path: String,
    pub chunk_idx: u64,
    pub total_chunks: u64,
    pub data_len: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChunkAck {
    pub chunk_idx: u64,
    pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferComplete {
    pub success: bool,
}