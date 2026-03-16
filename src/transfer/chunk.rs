use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::config::{CHUNK_SIZE, RESUME_EXT};

/// 전송할 파일 하나의 메타데이터
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// 전송 시 상대 경로 (루트 기준)
    pub relative_path: String,
    pub size: u64,
    pub blake3_hash: String,
    pub total_chunks: u64,
}

/// 전체 전송 매니페스트 (파일 목록 + 메타)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferManifest {
    pub files: Vec<FileEntry>,
    pub total_size: u64,
    pub total_files: usize,
}

/// Resume 상태 — 수신 측에서 저장
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkState {
    pub relative_path: String,
    pub total_chunks: u64,
    pub received_chunks: Vec<u64>, // 받은 청크 번호 목록
    pub size: u64,
}

impl ChunkState {
    pub fn new(entry: &FileEntry) -> Self {
        ChunkState {
            relative_path: entry.relative_path.clone(),
            total_chunks: entry.total_chunks,
            received_chunks: Vec::new(),
            size: entry.size,
        }
    }

    pub fn resume_path(output_dir: &Path, relative_path: &str) -> PathBuf {
        let safe = relative_path.replace(['/', '\\'], "_");
        output_dir.join(format!("{}{}", safe, RESUME_EXT))
    }

    pub fn load(output_dir: &Path, relative_path: &str) -> Option<Self> {
        let path = Self::resume_path(output_dir, relative_path);
        let content = std::fs::read_to_string(&path).ok()?;
        serde_yaml_ng::from_str(&content).ok()
    }

    pub fn save(&self, output_dir: &Path) -> Result<()> {
        let path = Self::resume_path(output_dir, &self.relative_path);
        let content = serde_yaml_ng::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn delete(&self, output_dir: &Path) {
        let path = Self::resume_path(output_dir, &self.relative_path);
        let _ = std::fs::remove_file(path);
    }

    pub fn is_chunk_received(&self, chunk_idx: u64) -> bool {
        self.received_chunks.contains(&chunk_idx)
    }

    pub fn next_chunk(&self) -> Option<u64> {
        for i in 0..self.total_chunks {
            if !self.is_chunk_received(i) {
                return Some(i);
            }
        }
        None
    }

    pub fn is_complete(&self) -> bool {
        self.received_chunks.len() as u64 == self.total_chunks
    }

    pub fn mark_received(&mut self, chunk_idx: u64) {
        if !self.is_chunk_received(chunk_idx) {
            self.received_chunks.push(chunk_idx);
        }
    }
}

/// 파일을 스캔해서 FileEntry 목록 생성
pub async fn scan_path(path: &Path) -> Result<Vec<FileEntry>> {
    let mut entries = Vec::new();
    scan_recursive(path, path, &mut entries).await?;
    Ok(entries)
}

fn scan_recursive<'a>(
    root: &'a Path,
    current: &'a Path,
    entries: &'a mut Vec<FileEntry>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let meta = std::fs::metadata(current)?;
        if meta.is_file() {
            // 숨김/시스템 파일 제외
            if should_skip(current) {
                return Ok(());
            }
            let entry = make_file_entry(root, current)?;
            entries.push(entry);
        } else if meta.is_dir() {
            let mut dir = tokio::fs::read_dir(current).await?;
            while let Some(item) = dir.next_entry().await? {
                let item_path = item.path();
                scan_recursive(root, &item_path, entries).await?;
            }
        }
        Ok(())
    })
}

fn should_skip(path: &Path) -> bool {
    // 파일명이 .으로 시작하는 숨김 파일 제외 (Linux/Mac)
    // desktop.ini, thumbs.db 등 Windows 시스템 파일 제외
    const SKIP_NAMES: &[&str] = &[
        "desktop.ini",
        "thumbs.db",
        "thumbs.db:encryptable",
        ".ds_store",
        ".localized",
    ];

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_lowercase();

        // .으로 시작하는 숨김 파일
        if lower.starts_with('.') {
            return true;
        }

        // Windows 시스템 파일
        if SKIP_NAMES.contains(&lower.as_str()) {
            return true;
        }
    }

    // Windows 시스템 속성 확인
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(path) {
            const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
            const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
            let attrs = meta.file_attributes();
            if attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0 {
                return true;
            }
        }
    }

    false
}

fn make_file_entry(root: &Path, file_path: &Path) -> Result<FileEntry> {
    let relative_path = if root.is_file() {
        // 단일 파일 전송: 파일명만
        file_path
            .file_name()
            .context("no filename")?
            .to_string_lossy()
            .to_string()
    } else {
        // 폴더 전송: 루트 폴더명 포함
        // C:\Photos\vacation\ 전송 시 → vacation/img1.jpg
        let folder_name = root
            .file_name()
            .context("no folder name")?
            .to_string_lossy()
            .to_string();
        let relative = file_path
            .strip_prefix(root)
            .context("strip prefix failed")?
            .to_string_lossy()
            .to_string();
        format!("{}/{}", folder_name, relative)
    };

    let size = std::fs::metadata(file_path)?.len();
    let total_chunks = (size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64;
    let total_chunks = total_chunks.max(1);

    let data = std::fs::read(file_path)?;
    let hash = blake3::hash(&data);
    let blake3_hash = format!("{}", hash.to_hex());

    Ok(FileEntry {
        relative_path,
        size,
        blake3_hash,
        total_chunks,
    })
}

/// 청크 오프셋 계산
pub fn chunk_offset(chunk_idx: u64) -> u64 {
    chunk_idx * CHUNK_SIZE as u64
}

pub fn chunk_size_for(file_size: u64, chunk_idx: u64) -> usize {
    let offset = chunk_offset(chunk_idx);
    let remaining = file_size.saturating_sub(offset);
    remaining.min(CHUNK_SIZE as u64) as usize
}
