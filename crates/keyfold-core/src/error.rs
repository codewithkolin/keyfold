use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a Keyfold vault: {0}")]
    InvalidFormat(&'static str),
    #[error("unsupported vault version {0}; update Keyfold")]
    UnsupportedVersion(u16),
    #[error("a file already exists at that location")]
    AlreadyExists,
    #[error("wrong password, or the vault header was modified")]
    WrongPassword,
    #[error("the vault failed authentication; the file was modified or corrupted")]
    Tampered,
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("serialisation error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("free plan limit reached: {0}")]
    LimitReached(Limit),
    #[error("item not found")]
    NotFound,
    #[error("invalid licence: {0}")]
    Licence(&'static str),
    #[error("this vault has no Recovery Kit")]
    NoRecovery,
    #[error("that recovery code does not open this vault")]
    WrongRecoveryCode,
    #[error("invalid 2FA secret: {0}")]
    Totp(&'static str),
    #[error("backup: {0}")]
    Backup(&'static str),
}

/// Which free-plan limit was hit, with the limit value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Projects(usize),
    Items(usize),
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Limit::Projects(1) => write!(f, "the free plan allows 1 project"),
            Limit::Projects(n) => write!(f, "the free plan allows {n} projects"),
            Limit::Items(n) => write!(f, "the free plan allows {n} items"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
