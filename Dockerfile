# The keyfold MCP server on Linux, for MCP directories that start a server in a sandbox to read
# its tool list. It answers the handshake and lists its tools by itself; every tool call needs
# the Keyfold app running and unlocked on the same computer, so in a container a call reports
# that Keyfold isn't running. To use Keyfold, install the Mac app: https://keyfold.app/download
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p keyfold-cli

FROM debian:bookworm-slim
COPY --from=build /src/target/release/keyfold /usr/local/bin/keyfold
ENTRYPOINT ["keyfold", "mcp"]
