# Keyfold threat model

Keyfold is an offline desktop vault. This document says what it protects against, what it does not, and why. It is written for users who want to judge the design and for researchers who want to break it.

## What Keyfold is

- One encrypted file (`.keyfold`) on the user's disk. No server, no account, no sync service, no telemetry.
- The desktop app opens no network connection unless the person allows a daily update check (Mac only; asked once, off if declined). The web view is always denied network access by the Tauri capability system and a strict Content Security Policy. The update check runs in Rust and fetches only a version file and, if the person clicks install, the signed update. The Windows app has no updater at all; the Microsoft Store updates it.
- Cryptography comes from audited Rust crates only (RustCrypto `argon2`, `chacha20poly1305`, `ed25519-dalek`). Keyfold contains no hand-written primitives.

## Assets

1. Secret values and passwords inside the vault.
2. The master passphrase.
3. The data encryption key (DEK) while the vault is unlocked.
4. Metadata: secret names, project names, URLs, notes. These are encrypted too; only the file header (key-derivation parameters, wrapped DEK) is plaintext.

## Attackers considered

| Attacker | Has | Keyfold's answer |
|---|---|---|
| Thief with the vault file (stolen laptop, leaked backup, cloud folder breach) | The `.keyfold` file, unlimited time | Argon2id at 64 MiB and 3 passes makes every guess cost about half a second of CPU and 64 MiB of RAM, which defeats GPU cracking. A 4-word random passphrase is out of reach for any realistic budget. A weak password is not: the strength meter exists for this reason. |
| Tamperer who edits the file | Write access to the file | Every byte is authenticated. The header is bound to the body as associated data, so changing KDF parameters, the salt, or the wrapped key makes decryption fail. The test suite flips every byte of a vault and checks that each flip is detected. |
| Malware on the user's machine while the vault is unlocked | User-level code execution | Out of scope for any password manager. Mitigations reduce exposure: auto-lock on idle and when hidden, values decrypted on demand and shown for 20 seconds, clipboard cleared after 30 seconds, and secret buffers zeroised on lock. |
| Memory forensics (RAM dump, swap, hibernation) after lock | Disk or memory image | The DEK and the decrypted body are wiped on lock via `zeroize`. Before lock, plaintext exists in memory; this is inherent. |
| Someone who steals a copy of the app binary | The installer | The binary contains no user data. A cracked binary only affects licensing. |
| Attacker with a stolen licence-signing key | Keyfold's private key | Can issue Pro licences. Cannot read any vault. The key lives only in the licence server's secret store and is never in the app. |
| Supply chain: malicious dependency | Publishing access to a crate or npm package | Dependency list kept minimal; lockfiles committed; `cargo audit` in CI. The web view has no network capability, so a malicious JavaScript dependency cannot exfiltrate. A malicious Rust dependency could, which is why the Rust dependency set stays small and pinned. |
| Attacker who controls the update feed or the download (compromised GitHub account, network attacker) | Ability to serve a crafted `latest.json` or archive | Every update archive must carry a minisign signature from Keyfold's updater key, which lives offline and is never on GitHub or in CI. The app checks the signature before installing and refuses a feed that announces a different version than the one recorded inside the signature, so an old signed release cannot be pushed as new. Release builds refuse to compile with the development updater key. |
| Malicious `.env` or imported data | Ability to make the user paste text | Imported text is treated as data. React escapes all rendered strings and the CSP forbids inline script, so no import can execute code. |

## Recovery Kit

A vault may carry a second wrap of its data key under a 160-bit random recovery code (see `docs/VAULT_FORMAT.md`). The code is shown once, when the vault is created or when the user asks for a new one, and Keyfold never stores or transmits it. It is equivalent to a second passphrase: whoever holds the printed kit can open the vault, so it must be kept apart from the vault file. There is no email or server based reset by design; a Keyfold-held master key would be a single target that opens every vault.

The optional plaintext hint in the header is visible to anyone with the file. Users are told to write only a nudge, never the passphrase.

## CLI and MCP server

The `keyfold` binary and the MCP server it starts (`keyfold mcp`) reach the app only through a local socket owned by the user (mode 0600 on macOS and Linux, a per-user named pipe on Windows). The app shows an approval sheet for every request and answers nothing until the user clicks. The client identity in that sheet (name, process id, executable path) is self-reported by the client process and therefore informational; the approval itself is the security boundary. Reads of values go only to the local client process, which writes a file or launches a command; the MCP tool results carry names, counts, exit codes and command output, never vault values. A one-hour grant is scoped to one client name, project and environment, and locking the vault clears all grants.

## Detection features (both opt-in, off by default)

The clipboard watcher polls the clipboard once a second only while the vault is unlocked and the setting is on. Text is matched in memory against provider patterns and an entropy rule; a match is held in Rust memory until the user saves or dismisses it (45-second timeout), and the value is never sent to the UI or written anywhere. Values that Keyfold itself copied are ignored. The folder watcher receives file-system events for chosen folders, reads only files named `.env*` (never `.env.example`, nothing under `node_modules`, `.git`, `target`, `dist`, `build`, `vendor`), and compares them with the vault; importing is always a click by the user. Both features can be switched off in Settings > Detection. Apple has announced clipboard-read prompts for macOS; if they arrive, the watcher needs one grant and otherwise stays silent.

## Explicitly out of scope

- A compromised operating system, kernel, or hardware.
- Shoulder surfing or screen recording while a value is revealed.
- The user forgetting the passphrase. There is no recovery by design; the alternative would be a backdoor.
- Denial of service, for example deleting the vault file. Keyfold keeps five rolling backups next to the file, and users are told to keep their own copies.

## Key facts a reviewer can check

- Vault format: `docs/VAULT_FORMAT.md`.
- Key derivation: `crates/keyfold-core/src/crypto.rs`, function `derive_kek`.
- Encryption and authentication: `crates/keyfold-core/src/crypto.rs`, functions `seal` and `open`; header binding in `crates/keyfold-core/src/vault.rs`, function `to_bytes`.
- Tamper test: `crates/keyfold-core/tests/vault.rs`, test `flipping_any_byte_is_detected`.
- What the app's interface can see (desktop app, not in the public repository): the vault snapshot sent to the web view carries names, tags and lengths but never values. A value travels only when you reveal or copy it, and 2FA secrets never leave Rust; the interface receives the current code.
- Web view permissions (desktop app): no filesystem, shell, or network permissions; files are read and written by Rust after a native dialog.
- Licence verification is offline: `crates/keyfold-core/src/licence.rs`.
- 2FA codes: `crates/keyfold-core/src/totp.rs`, checked against the RFC 6238 test vectors.
- What an AI agent can ask for: `crates/keyfold-agent/src/lib.rs` (the full request list) and `crates/keyfold-cli/src/mcp.rs` (the MCP tools). None returns a secret value.

## Reporting a vulnerability

Email security@keyfold.app. Please give us 90 days before public disclosure. We will credit you in the release notes unless you prefer otherwise.
