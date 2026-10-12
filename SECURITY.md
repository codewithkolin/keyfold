# Security policy

Keyfold stores secrets, so security reports get priority over everything else.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting: the **Security** tab of this repository, then **Report a vulnerability**. You will get a reply within 72 hours.

Useful details: the affected crate and version, what an attacker needs (a stolen vault file, local access, a malicious `.env`, and so on), and steps or a test that reproduces it.

## Scope

- `crates/keyfold-core`: key derivation, encryption, the vault file format, the Recovery Kit, licence verification and 2FA codes.
- `crates/keyfold-agent` and `crates/keyfold-cli`: the local socket protocol and the MCP server, including anything that would let an AI agent read a secret value.

The desktop app is not in this repository, but reports about it are welcome through the same channel.

## What to expect

Confirmed issues are fixed in a release before details are published. With your permission, you are credited in the changelog.
