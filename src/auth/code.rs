use rand::RngExt;

const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const SEGMENT_LEN: usize = 4;
const SEGMENTS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCode(String);

impl AuthCode {
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let segments: Vec<String> = (0..SEGMENTS)
            .map(|_| {
                (0..SEGMENT_LEN)
                    .map(|_| {
                        let idx = rng.random_range(0..CHARSET.len());
                        CHARSET[idx] as char
                    })
                    .collect()
            })
            .collect();
        AuthCode(segments.join("-"))
    }

    pub fn verify(&self, other: &str) -> bool {
        let a = self.0.as_bytes();
        let b = other.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

impl std::fmt::Display for AuthCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for AuthCode {
    fn from(s: String) -> Self {
        AuthCode(s)
    }
}

impl From<&str> for AuthCode {
    fn from(s: &str) -> Self {
        AuthCode(s.to_string())
    }
}