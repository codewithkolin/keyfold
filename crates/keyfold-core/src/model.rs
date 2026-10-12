use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Everything inside the encrypted body. Wiped from memory on drop.
#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct VaultBody {
    #[serde(default = "schema_v1")]
    pub schema: u32,
    #[serde(default)]
    pub projects: Vec<Project>,
    #[serde(default)]
    pub passwords: Vec<PasswordEntry>,
}

fn schema_v1() -> u32 {
    1
}

impl Default for VaultBody {
    fn default() -> Self {
        Self {
            schema: 1,
            projects: Vec::new(),
            passwords: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Project {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub color: String,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub environments: Vec<Environment>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Environment {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub order: u32,
    #[serde(default)]
    pub secrets: Vec<Secret>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    pub id: String,
    /// e.g. STRIPE_SECRET_KEY
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}
