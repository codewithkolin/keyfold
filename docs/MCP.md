# Keyfold for AI agents and the command line

Keyfold ships one extra binary, `keyfold`. It talks to the running Keyfold app over a local socket. **Every request is approved by you in the Keyfold window**, and the app never hands secret values to an AI model: the MCP tools write `.env` files or run commands on the agent's behalf.

## Command line

```
keyfold projects                                  # project and environment names
keyfold names -p acme -e production               # secret names only
keyfold env -p acme -e production                 # writes ./.env (add it to .gitignore)
keyfold env -p acme -e production --stdout        # prints instead
keyfold run -p acme -e production -- npm start    # injects secrets as environment variables
```

If Keyfold is locked, the command says so; unlock the app and run it again. "Allow for 1 hour" in the approval sheet covers the same project and environment for that client, so a `keyfold run` loop does not prompt every time.

## MCP server for Cursor, Claude Code, and others

Start it with `keyfold mcp`. It speaks MCP over stdin/stdout.

**Claude Code**

```
claude mcp add keyfold -- keyfold mcp
```

**Cursor** (`.cursor/mcp.json` in the project, or the global one)

```json
{
  "mcpServers": {
    "keyfold": { "command": "keyfold", "args": ["mcp"] }
  }
}
```

### Tools

| Tool | What it does | What the model sees |
|---|---|---|
| `keyfold_projects` | List projects and environments | Names and counts |
| `keyfold_secret_names` | List secret names in an environment | Names only |
| `keyfold_write_env` | Write a `.env` file for an environment at a path | Number of keys written |
| `keyfold_run` | Run a shell command with the environment injected | Exit code and output (truncated to 20 KB). Secret values appear only if the command prints them |
| `keyfold_store` | Add or update one secret | Confirmation |

There is deliberately no "reveal" tool. A prompt injection inside the agent cannot ask Keyfold for values; the worst it can do is run a command that prints them, which you see in the approval sheet before it runs.

### The approval sheet

Each request shows the client name and process id, the action, and whether it reads values. Choices: Deny, Allow once, Allow for 1 hour (same client, project and environment). Requests time out after three minutes if nobody answers. Locking Keyfold cancels all grants.

### Socket

macOS: `~/Library/Application Support/com.cwksolutions.keyfold/agent.sock`, mode 0600. Windows: named pipe `com.cwksolutions.keyfold.agent`. Only processes running as your user can reach it.
