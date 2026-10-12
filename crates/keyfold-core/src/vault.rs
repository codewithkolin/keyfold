//! Create, open, save. Envelope encryption: password -> KEK wraps a random DEK,
//! DEK encrypts the body. See docs/VAULT_FORMAT.md.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::format::{self, Header, KdfParams, Parsed, RecoveryHeader, WrappedKey};
use crate::model::VaultBody;
use crate::recovery::RecoveryCode;
use crate::time::now_ms;

pub const BACKUP_COUNT: u8 = 5;
/// Longest passphrase hint, in characters.
pub const HINT_MAX: usize = 80;

/// Tunable Argon2id cost. Stored in the header so it can be raised later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfSettings {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfSettings {
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl From<&KdfParams> for KdfSettings {
    fn from(p: &KdfParams) -> Self {
        Self {
            m_cost_kib: p.m_cost_kib,
            t_cost: p.t_cost,
            p_cost: p.p_cost,
        }
    }
}

pub struct Vault {
    path: PathBuf,
    header: Header,
    dek: Zeroizing<[u8; KEY_LEN]>,
    pub body: VaultBody,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("vault_id", &self.header.vault_id)
            .finish()
    }
}

fn b64d(s: &str, expect: usize, what: &'static str) -> Result<Vec<u8>> {
    let v = B64.decode(s).map_err(|_| Error::InvalidFormat(what))?;
    if v.len() != expect {
        return Err(Error::InvalidFormat(what));
    }
    Ok(v)
}

fn to_array<const N: usize>(v: &[u8]) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(v);
    a
}

fn wrap_dek(kek: &[u8; KEY_LEN], dek: &[u8; KEY_LEN], vault_id: &str) -> Result<WrappedKey> {
    let nonce = crypto::random_bytes::<NONCE_LEN>()?;
    let ct = crypto::seal(kek, &nonce, dek, vault_id.as_bytes())?;
    Ok(WrappedKey {
        nonce: B64.encode(nonce),
        ct: B64.encode(ct),
    })
}

fn unwrap_dek(kek: &[u8; KEY_LEN], header: &Header) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let nonce = b64d(&header.wrapped_dek.nonce, NONCE_LEN, "wrapped key nonce")?;
    let ct = b64d(&header.wrapped_dek.ct, KEY_LEN + TAG_LEN, "wrapped key")?;
    let pt = crypto::open(
        kek,
        &to_array::<NONCE_LEN>(&nonce),
        &ct,
        header.vault_id.as_bytes(),
    )
    .map_err(|_| Error::WrongPassword)?;
    if pt.len() != KEY_LEN {
        return Err(Error::WrongPassword);
    }
    Ok(Zeroizing::new(to_array::<KEY_LEN>(&pt)))
}

fn kdf_params(settings: KdfSettings, salt: &[u8; SALT_LEN]) -> KdfParams {
    KdfParams {
        algo: "argon2id".into(),
        version: 19,
        m_cost_kib: settings.m_cost_kib,
        t_cost: settings.t_cost,
        p_cost: settings.p_cost,
        salt: B64.encode(salt),
    }
}

impl Vault {
    /// Create a new vault file. Fails if the path already exists.
    pub fn create(
        path: impl Into<PathBuf>,
        password: &[u8],
        settings: KdfSettings,
    ) -> Result<Self> {
        let path = path.into();
        if path.exists() {
            return Err(Error::AlreadyExists);
        }
        if password.is_empty() {
            return Err(Error::InvalidFormat("password is empty"));
        }
        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let kek = crypto::derive_kek(password, &salt, &settings)?;
        let dek = Zeroizing::new(crypto::random_bytes::<KEY_LEN>()?);
        let vault_id = uuid::Uuid::new_v4().to_string();
        let wrapped_dek = wrap_dek(&kek, &dek, &vault_id)?;
        let header = Header {
            vault_id,
            created_at: now_ms(),
            kdf: kdf_params(settings, &salt),
            wrapped_dek,
            hint: None,
            recovery: None,
            hw_key: None,
        };
        let mut v = Vault {
            path,
            header,
            dek,
            body: VaultBody::default(),
        };
        v.save()?;
        Ok(v)
    }

    /// Open with the master password.
    pub fn open(path: impl Into<PathBuf>, password: &[u8]) -> Result<Self> {
        let path = path.into();
        let bytes = read_limited(&path)?;
        Self::from_bytes(path, &bytes, password)
    }

    /// Open from bytes already in memory (tests, and the biometric path).
    pub fn from_bytes(path: impl Into<PathBuf>, bytes: &[u8], password: &[u8]) -> Result<Self> {
        let parsed = format::parse(bytes)?;
        if parsed.header.kdf.algo != "argon2id" {
            return Err(Error::InvalidFormat("unknown key derivation"));
        }
        let salt = b64d(&parsed.header.kdf.salt, SALT_LEN, "salt")?;
        let settings = KdfSettings::from(&parsed.header.kdf);
        let kek = crypto::derive_kek(password, &salt, &settings)?;
        let dek = unwrap_dek(&kek, &parsed.header)?;
        Self::decrypt_body(path.into(), parsed, dek)
    }

    /// Open with a DEK obtained from the biometric-protected keychain entry.
    pub fn open_with_dek(path: impl Into<PathBuf>, dek: Zeroizing<[u8; KEY_LEN]>) -> Result<Self> {
        let path = path.into();
        let bytes = read_limited(&path)?;
        let parsed = format::parse(&bytes)?;
        Self::decrypt_body(path, parsed, dek)
    }

    fn decrypt_body(
        path: PathBuf,
        parsed: Parsed<'_>,
        dek: Zeroizing<[u8; KEY_LEN]>,
    ) -> Result<Self> {
        if parsed.body.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::InvalidFormat("body too short"));
        }
        let nonce = to_array::<NONCE_LEN>(&parsed.body[..NONCE_LEN]);
        let pt = crypto::open(&dek, &nonce, &parsed.body[NONCE_LEN..], parsed.prefix)?;
        let body: VaultBody = serde_json::from_slice(&pt).map_err(|_| Error::Tampered)?;
        Ok(Vault {
            path,
            header: parsed.header,
            dek,
            body,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn vault_id(&self) -> &str {
        &self.header.vault_id
    }

    pub fn kdf_settings(&self) -> KdfSettings {
        KdfSettings::from(&self.header.kdf)
    }

    /// A copy of the data key, for wrapping into the biometric keychain entry.
    pub fn dek(&self) -> Zeroizing<[u8; KEY_LEN]> {
        self.dek.clone()
    }

    /// Serialise and encrypt the whole file into memory.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let prefix = format::encode_prefix(&self.header)?;
        let pt = Zeroizing::new(serde_json::to_vec(&self.body)?);
        let nonce = crypto::random_bytes::<NONCE_LEN>()?;
        let ct = crypto::seal(&self.dek, &nonce, &pt, &prefix)?;
        let mut out = prefix;
        out.extend_from_slice(&((NONCE_LEN + ct.len()) as u64).to_le_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Atomic save with rolling backups.
    pub fn save(&mut self) -> Result<()> {
        let bytes = self.to_bytes()?;
        write_atomic(&self.path, &bytes)?;
        Ok(())
    }

    /// Write an encrypted copy of this vault to `dest`. The copy opens with the same
    /// passphrase and recovery code. `dest` must not be the vault or one of its rolling backups.
    pub fn export_backup(&self, dest: &Path) -> Result<()> {
        if is_vault_or_rolling_backup(dest, &self.path) {
            return Err(Error::Backup(
                "choose a location other than the vault and its automatic backups",
            ));
        }
        let bytes = self.to_bytes()?;
        write_file_atomic(dest, &bytes)
    }

    /// Make an opened backup the vault at `target`. Opening the backup already proved its
    /// passphrase or recovery code; the file currently at `target` becomes its newest rolling backup.
    pub fn restore_into(mut self, target: &Path) -> Result<Self> {
        if same_path(&self.path, target) {
            return Err(Error::Backup("that file is already the open vault"));
        }
        self.path = target.to_path_buf();
        self.save()?;
        Ok(self)
    }

    /// Verify the current password, then re-wrap the DEK under a new one.
    pub fn change_password(
        &mut self,
        current: &[u8],
        new: &[u8],
        settings: KdfSettings,
    ) -> Result<()> {
        let salt = b64d(&self.header.kdf.salt, SALT_LEN, "salt")?;
        let kek = crypto::derive_kek(current, &salt, &self.kdf_settings())?;
        unwrap_dek(&kek, &self.header)?;
        self.set_password(new, settings)
    }

    /// Re-wrap the DEK under a new password without checking the old one.
    /// Only reachable once the vault is already open (password, recovery code, or biometrics).
    pub fn set_password(&mut self, new: &[u8], settings: KdfSettings) -> Result<()> {
        if new.is_empty() {
            return Err(Error::InvalidFormat("password is empty"));
        }
        let new_salt = crypto::random_bytes::<SALT_LEN>()?;
        let new_kek = crypto::derive_kek(new, &new_salt, &settings)?;
        self.header.wrapped_dek = wrap_dek(&new_kek, &self.dek, &self.header.vault_id)?;
        self.header.kdf = kdf_params(settings, &new_salt);
        self.save()
    }

    // ----- passphrase hint -----

    pub fn hint(&self) -> Option<&str> {
        self.header.hint.as_deref()
    }

    /// Set or clear the plaintext hint. Trimmed; empty means none; at most `HINT_MAX` characters.
    pub fn set_hint(&mut self, hint: Option<&str>) -> Result<()> {
        let cleaned = hint
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string);
        if let Some(h) = &cleaned {
            if h.chars().count() > HINT_MAX {
                return Err(Error::InvalidFormat("hint is too long"));
            }
        }
        self.header.hint = cleaned;
        self.save()
    }

    /// Read the hint from a locked vault file. Parses only the header.
    pub fn read_hint(path: &Path) -> Result<Option<String>> {
        let bytes = read_limited(path)?;
        Ok(format::parse(&bytes)?.header.hint)
    }

    // ----- Recovery Kit -----

    pub fn has_recovery(&self) -> bool {
        self.header.recovery.is_some()
    }

    /// Does a locked vault file carry a Recovery Kit wrap?
    pub fn read_has_recovery(path: &Path) -> Result<bool> {
        let bytes = read_limited(path)?;
        Ok(format::parse(&bytes)?.header.recovery.is_some())
    }

    /// Create (or replace) the recovery wrap and return the new code. Any previous code stops working.
    pub fn enable_recovery(&mut self) -> Result<RecoveryCode> {
        let code = RecoveryCode::generate()?;
        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let key = code.derive_key(&salt)?;
        self.header.recovery = Some(RecoveryHeader {
            salt: B64.encode(salt),
            wrapped_dek: wrap_dek(&key, &self.dek, &self.header.vault_id)?,
            created_at: now_ms(),
        });
        self.save()?;
        Ok(code)
    }

    pub fn disable_recovery(&mut self) -> Result<()> {
        self.header.recovery = None;
        self.save()
    }

    /// Open with a Recovery Kit code instead of the password.
    pub fn open_with_recovery(path: impl Into<PathBuf>, code: &RecoveryCode) -> Result<Self> {
        let path = path.into();
        let bytes = read_limited(&path)?;
        let parsed = format::parse(&bytes)?;
        let rec = parsed.header.recovery.as_ref().ok_or(Error::NoRecovery)?;
        let salt = b64d(&rec.salt, SALT_LEN, "recovery salt")?;
        let key = code.derive_key(&salt)?;
        let nonce = b64d(&rec.wrapped_dek.nonce, NONCE_LEN, "recovery nonce")?;
        let ct = b64d(
            &rec.wrapped_dek.ct,
            KEY_LEN + TAG_LEN,
            "recovery wrapped key",
        )?;
        let pt = crypto::open(
            &key,
            &to_array::<NONCE_LEN>(&nonce),
            &ct,
            parsed.header.vault_id.as_bytes(),
        )
        .map_err(|_| Error::WrongRecoveryCode)?;
        if pt.len() != KEY_LEN {
            return Err(Error::WrongRecoveryCode);
        }
        let dek = Zeroizing::new(to_array::<KEY_LEN>(&pt));
        Self::decrypt_body(path, parsed, dek)
    }
}

fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    if len > format::max_file_len() as u64 {
        return Err(Error::InvalidFormat("file too large to be a vault"));
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

pub fn backup_path(path: &Path, n: u8) -> PathBuf {
    with_suffix(path, &format!(".bak{n}"))
}

fn rotate_backups(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    for n in (1..BACKUP_COUNT).rev() {
        let from = backup_path(path, n);
        if from.exists() {
            fs::rename(&from, backup_path(path, n + 1))?;
        }
    }
    fs::copy(path, backup_path(path, 1))?;
    Ok(())
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn is_vault_or_rolling_backup(candidate: &Path, vault: &Path) -> bool {
    same_path(candidate, vault)
        || (1..=BACKUP_COUNT).any(|n| same_path(candidate, &backup_path(vault, n)))
        || same_path(candidate, &with_suffix(vault, ".tmp"))
}

/// Temp file, fsync, rename; no rolling backups (for files that are not the vault).
fn write_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = with_suffix(path, ".tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let tmp = with_suffix(path, ".tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    rotate_backups(path)?;
    fs::rename(&tmp, path)?;
    Ok(())
}
