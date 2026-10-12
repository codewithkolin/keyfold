# Keyfold core

The open-source parts of [Keyfold](https://keyfold.app), an offline-first vault for developers: API keys organised by project and environment, plus passwords, in one encrypted file. No account, no cloud, no telemetry.

The desktop app (macOS and Windows) is built on these crates. Downloads are on the [Releases](https://github.com/codewithkolin/keyfold/releases) page.

## What is here

| Crate | What it does |
|---|---|
| [`crates/keyfold-core`](crates/keyfold-core) | Argon2id key derivation, XChaCha20-Poly1305 envelope encryption, the tamper-evident vault format, rolling backups, the Recovery Kit, `.env` parsing, key detection patterns, 2FA codes (RFC 6238) and offline Ed25519 licence verification |
| [`crates/keyfold-agent`](crates/keyfold-agent) | The JSON-line protocol between the `keyfold` CLI and the running app, over an owner-only local socket |
| [`crates/keyfold-cli`](crates/keyfold-cli) | The `keyfold` command line and the MCP server for Cursor and Claude Code. No tool returns a secret value; every request is approved in the app |

## Docs

- [Vault format](docs/VAULT_FORMAT.md): every byte of the file, and how it is authenticated.
- [Threat model](docs/THREAT_MODEL.md): what Keyfold protects against, and what it cannot.
- [MCP and CLI guide](docs/MCP.md): connecting an AI agent without showing it your keys.

## Build and test

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p keyfold-cli   # the `keyfold` binary
```

Rust stable, no other toolchain needed.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Licence

AGPL-3.0-only. See the `LICENSE` file in each crate. The Keyfold desktop app around these crates is proprietary.
