use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::config::known_peers_path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub transfer_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnownPeers {
    #[serde(default)]
    pub send_peers: Vec<PeerEntry>,
    #[serde(default)]
    pub recv_peers: Vec<PeerEntry>,
}

impl KnownPeers {
    pub fn load() -> Result<Self> {
        let path = known_peers_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let peers: KnownPeers = serde_yaml_ng::from_str(&content)
            .with_context(|| "failed to parse known_peers.yaml")?;
        Ok(peers)
    }

    pub fn save(&self) -> Result<()> {
        let path = known_peers_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // 파일 락 획득
        let lock_path = path.with_extension("lock");
        let mut lock = fslock::LockFile::open(&lock_path)?;
        lock.lock()?;

        // 저장 직전 파일 다시 읽어서 merge
        let mut current = if path.exists() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            serde_yaml_ng::from_str::<KnownPeers>(&content).unwrap_or_default()
        } else {
            KnownPeers::default()
        };

        // send_peers merge
        for entry in &self.send_peers {
            if let Some(existing) = current.send_peers.iter_mut().find(|p| p.ip == entry.ip) {
                // eprintln!("DEBUG: updating port {} -> {}", existing.port, entry.port);
                existing.port = entry.port;
                existing.last_seen = entry.last_seen;
                existing.transfer_count = entry.transfer_count;
                existing.public_key = entry.public_key.clone();
                if entry.alias.is_some() {
                    existing.alias = entry.alias.clone();
                }
            } else {
                current.send_peers.push(entry.clone());
            }
        }

        // recv_peers merge
        for entry in &self.recv_peers {
            if let Some(existing) = current.recv_peers.iter_mut().find(|p| p.ip == entry.ip) {
                existing.port = entry.port;
                existing.last_seen = entry.last_seen;
                existing.transfer_count = entry.transfer_count;
                existing.public_key = entry.public_key.clone();
                if entry.alias.is_some() {
                    existing.alias = entry.alias.clone();
                }
            } else {
                current.recv_peers.push(entry.clone());
            }
        }

        current.send_peers.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        current.recv_peers.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

        let content = serde_yaml_ng::to_string(&current)?;
        std::fs::write(&path, content)
            .with_context(|| format!("failed to write {}", path.display()))?;
        // eprintln!("DEBUG: saved to {}", path.display());
        // eprintln!("DEBUG: content = {}", serde_yaml_ng::to_string(&current).unwrap());

        lock.unlock()?;
        Ok(())
    }

    pub fn find_send_peer(&self, ip: &str) -> Option<&PeerEntry> {
        self.send_peers.iter().find(|p| p.ip == ip)
    }

    pub fn find_recv_peer(&self, ip: &str) -> Option<&PeerEntry> {
        self.recv_peers.iter().find(|p| p.ip == ip)
    }

    pub fn upsert_send_peer(&mut self, entry: PeerEntry) {
        if let Some(existing) = self.send_peers.iter_mut().find(|p| p.ip == entry.ip) {
            existing.last_seen = entry.last_seen;
            existing.transfer_count = entry.transfer_count;
            existing.public_key = entry.public_key;
            existing.port = entry.port;
            if entry.alias.is_some() {
                existing.alias = entry.alias;
            }
        } else {
            self.send_peers.push(entry);
        }
        self.send_peers.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    }

    pub fn upsert_recv_peer(&mut self, entry: PeerEntry) {
        if let Some(existing) = self.recv_peers.iter_mut().find(|p| p.ip == entry.ip) {
            existing.last_seen = entry.last_seen;
            existing.transfer_count = entry.transfer_count;  // send와 동일하게
            existing.public_key = entry.public_key;
            existing.port = entry.port;
            if entry.alias.is_some() {
                existing.alias = entry.alias;
            }
        } else {
            self.recv_peers.push(entry);
        }
        self.recv_peers.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    }

    pub fn latest_send_peer(&self) -> Option<&PeerEntry> {
        self.send_peers.first()
    }

    pub fn send_peer_by_index(&self, index: usize) -> Option<&PeerEntry> {
        if index == 0 { return None; }
        self.send_peers.get(index - 1)
    }

    pub fn print_send_list(&self) {
        if self.send_peers.is_empty() {
            println!("No send history found.");
            return;
        }
        println!(
            "  {:<4} {:<20} {:<8} {:<16} {:<12} {}",
            "#", "IP", "PORT", "ALIAS", "TRANSFERS", "LAST SEEN"
        );
        println!("  {}", "-".repeat(75));
        for (i, peer) in self.send_peers.iter().enumerate() {
            let alias = peer.alias.as_deref().unwrap_or("-");
            let last_seen = peer.last_seen.format("%Y-%m-%d %H:%M").to_string();
            let marker = if i == 0 { "← latest" } else { "" };
            println!(
                "  {:<4} {:<20} {:<8} {:<16} {:<12} {} {}",
                i + 1, peer.ip, peer.port, alias, peer.transfer_count, last_seen, marker
            );
        }
    }
}
