//! Keyfold vault core.
//!
//! Pure Rust, no UI, no network. Everything the desktop app and (later) the
//! CLI need to create, open, edit, and save an encrypted `.keyfold` vault.
//! See `docs/VAULT_FORMAT.md` for the on-disk format.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod envfile;
pub mod error;
pub mod format;
pub mod licence;
pub mod model;
pub mod patterns;
pub mod recovery;
pub mod store;
pub mod time;
pub mod totp;
pub mod vault;

pub use error::{Error, Limit, Result};
pub use licence::{Licence, LicencePlan};
pub use model::*;
pub use patterns::{classify, Detection};
pub use recovery::RecoveryCode;
pub use store::{Limits, PasswordInput, Plan, SecretInput};
pub use vault::{KdfSettings, Vault};
