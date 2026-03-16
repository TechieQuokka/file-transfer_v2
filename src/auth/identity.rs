use anyhow::{Context, Result};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::path::PathBuf;

use crate::config::identity_dir;

#[derive(Debug, Clone)]
pub struct Identity {
    pub public_key_b64: String,
}

impl Identity {
    pub fn load_or_create() -> Result<Self> {
        let dir = identity_dir();
        std::fs::create_dir_all(&dir)?;

        let priv_path = dir.join(crate::config::PRIVATE_KEY_FILE);
        let pub_path = dir.join(crate::config::PUBLIC_KEY_FILE);

        if priv_path.exists() && pub_path.exists() {
            let public_key_b64 = std::fs::read_to_string(&pub_path)
                .with_context(|| "failed to read public key")?
                .trim()
                .to_string();
            Ok(Identity { public_key_b64 })
        } else {
            Self::generate_and_save(&priv_path, &pub_path)
        }
    }

    fn generate_and_save(priv_path: &PathBuf, pub_path: &PathBuf) -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow::anyhow!("Ed25519 key generation failed"))?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| anyhow::anyhow!("Ed25519 key parse failed"))?;

        let private_key_b64 = base64_encode(pkcs8.as_ref());
        let public_key_b64 = base64_encode(key_pair.public_key().as_ref());

        std::fs::write(priv_path, &private_key_b64)?;
        std::fs::write(pub_path, &public_key_b64)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(priv_path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(Identity { public_key_b64 })
    }
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        out.push(ALPHABET[b0 >> 2] as char);
        out.push(ALPHABET[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((b1 & 15) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[b2 & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}
