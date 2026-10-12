# Keyfold vault file format, version 1

One file, extension `.keyfold`. Everything after the header is encrypted. The header is plaintext but tamper-evident, because it is bound to the body as associated data.

## Layout

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `KEYFOLD\0` |
| 8 | 2 | format version, little-endian u16, currently `1` |
| 10 | 4 | header length `H`, little-endian u32 |
| 14 | H | header, UTF-8 JSON (see below) |
| 14+H | 8 | body length `B`, little-endian u64 |
| 22+H | B | body: 24-byte XChaCha20-Poly1305 nonce, then ciphertext with 16-byte tag |

## Header JSON

```json
{
  "vault_id": "uuid v4",
  "created_at": "unix milliseconds",
  "kdf": {
    "algo": "argon2id",
    "version": 19,
    "m_cost_kib": 65536,
    "t_cost": 3,
    "p_cost": 1,
    "salt": "base64, 32 random bytes"
  },
  "wrapped_dek": {
    "nonce": "base64, 24 random bytes",
    "ct": "base64, 32-byte DEK + 16-byte tag"
  },
  "hint": "optional plaintext passphrase hint, at most 80 characters",
  "recovery": {
    "salt": "base64, 32 random bytes",
    "wrapped_dek": { "nonce": "base64, 24 bytes", "ct": "base64, 32-byte DEK + 16-byte tag" },
    "created_at": 0
  },
  "hw_key": null
}
```

`hint` and `recovery` are optional and omitted when unset. `recovery` is a second wrap of the DEK under `HKDF-SHA256(ikm = recovery code bytes, salt, info = "keyfold/recovery/v1")`. The recovery code is 160 random bits shown as Crockford base32 (`KFLD-XXXX-…`), so a fast KDF is safe. Turning the kit off removes the field; generating a new code replaces it.

`hw_key` is reserved for version 1.1 (YubiKey). When present it holds the challenge and the key slot; the response is mixed into the KEK with HKDF-SHA256.

## Keys

- **KEK** (key encryption key, 32 bytes) = Argon2id(password, salt, params). Never stored.
- **DEK** (data encryption key, 32 bytes) = random. Stored only as `wrapped_dek`, which is XChaCha20-Poly1305(KEK, nonce, DEK, aad = `vault_id`).
- Changing the password derives a new KEK and rewrites `wrapped_dek` only. The body is untouched.
- Biometric quick unlock stores a second wrap of the DEK outside the vault file, in the OS keychain entry the biometric plugin protects, keyed by `vault_id`. Deleting the vault or disabling biometrics deletes that entry.

## Body

`body = nonce || XChaCha20-Poly1305(DEK, nonce, plaintext, aad = magic || version || header_len || header_bytes)`

The associated data binds the header to the body: any edit to the KDF parameters, salt, or wrapped DEK makes decryption fail with an authentication error. A fresh random nonce is used on every save.

Plaintext is UTF-8 JSON:

```json
{
  "schema": 1,
  "projects": [
    {
      "id": "uuid", "name": "Acme API", "color": "violet", "created_at": "...", "updated_at": "...",
      "environments": [
        {
          "id": "uuid", "name": "production", "order": 0,
          "secrets": [
            {
              "id": "uuid", "key": "STRIPE_SECRET_KEY", "value": "sk_live_...",
              "notes": "", "tags": ["payments"], "url": "https://dashboard.stripe.com",
              "expires_at": null, "created_at": "...", "updated_at": "..."
            }
          ]
        }
      ]
    }
  ],
  "passwords": [
    {
      "id": "uuid", "title": "GitHub", "username": "suman", "password": "...",
      "url": "https://github.com", "notes": "", "totp_secret": null, "tags": [],
      "created_at": "...", "updated_at": "..."
    }
  ]
}
```

Version 1 encrypts the whole body as one unit rather than per record. Vaults are small (kilobytes), so this is fast, and it removes a whole class of bugs around per-record nonce handling. While unlocked, the decrypted body lives in process memory inside `Zeroizing` buffers and is wiped on lock.

## Writing

1. Serialise the body, encrypt, assemble the full file in memory.
2. Write to `<path>.tmp` in the same directory, `fsync`.
3. Rotate backups: `<path>.bak5` ← `.bak4` ← ... ← `.bak1` ← current file.
4. Rename `<path>.tmp` over `<path>` (atomic on macOS and Windows).

## Opening

1. Check magic and version. Refuse unknown versions with a clear error.
2. Parse the header. Derive the KEK from the password. Unwrap the DEK; failure means wrong password or tampered header.
3. Decrypt the body with the header bytes as associated data. Failure means the file was modified after the header check.

## Defaults and limits

- Argon2id 64 MiB, 3 passes, 1 lane: about 0.3 to 0.6 s on a 2020-era laptop. Parameters live in the header so future versions can raise them and rewrap on the next password change.
- Maximum header 64 KiB, maximum body 256 MiB. Larger files are refused before allocation.

## Free tier

The core enforces the free tier when a licence is absent: 1 project, 25 items (secrets plus passwords). Existing data over the limit is never deleted; only adding is blocked.
