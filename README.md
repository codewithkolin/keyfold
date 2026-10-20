# Keyfold core

The open-source parts of [Keyfold](https://keyfold.app), an offline-first vault for developers: API keys organised by project and environment, plus passwords, in one encrypted file. No account, no cloud, no telemetry.

The Keyfold app for Mac is built on these crates (Windows is coming through the Microsoft Store). Get it at [keyfold.app/download](https://keyfold.app/download); signed builds are also on the [Releases](https://github.com/codewithkolin/keyfold/releases) page.

## What is here

| Crate | What it does |
|---|---|
| [`crates/keyfold-core`](crates/keyfold-core) | Argon2id key derivation, XChaCha20-Poly1305 envelope encryption, the tamper-evident vault format, rolling backups, the Recovery Kit, `.env` parsing, key detection patterns, 2FA codes (RFC 6238) and offline Ed25519 licence verification |
| [`crates/keyfold-agent`](crates/keyfold-agent) | The JSON-line protocol between the `keyfold` CLI and the running app, over an owner-only local socket |
| [`crates/keyfold-cli`](crates/keyfold-cli) | The `keyfold` command line and the MCP server for Cursor and Claude Code. No tool returns a secret value; every request is approved in the app |

## Use it with an AI agent (MCP)

`keyfold mcp` lets Claude Code, Cursor, Codex, Gemini CLI and other MCP clients use your API keys without the model seeing them. Its seven tools list project and key names, write a `.env` file you approve, run a command with the keys injected, store a key, create a project and import a `.env` file. None of them returns a secret value. Every request waits for your click in the Keyfold app, which shows the command or file the keys are for.

1. Install [Keyfold for Mac](https://keyfold.app/download). In the app, open Settings › General › Command line and MCP and click Install, which puts `keyfold` on your `PATH`.
2. Add the server to your client:

```
claude mcp add --scope user keyfold -- keyfold mcp
```

Cursor (`.cursor/mcp.json`): `{ "mcpServers": { "keyfold": { "command": "keyfold", "args": ["mcp"] } } }`

A command you approve can still print a key, and the model reads what it prints; the [MCP guide](docs/MCP.md) covers that and one-hour approvals. The server needs the Keyfold app running and unlocked on the same Mac. The [`Dockerfile`](Dockerfile) builds it on Linux only so that MCP directories can read its tool list.

MCP Registry name: `mcp-name: io.github.codewithkolin/keyfold`

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
