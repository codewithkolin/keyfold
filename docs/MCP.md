# Keyfold for AI agents and the command line

Keyfold ships one extra binary, `keyfold`. It talks to the running Keyfold app over a local socket. **Every request is approved by you in the Keyfold window**, and the app never hands secret values to an AI model: the MCP tools write `.env` files or run commands on the agent's behalf.

## Get the `keyfold` command

On a Mac it comes inside the app from 1.0.1: `/Applications/Keyfold.app/Contents/MacOS/keyfold`. To use it by name, open **Settings › General › Command line and MCP** and click **Install**: that links `/usr/local/bin/keyfold` to the app's copy (macOS asks for your password if that folder isn't yours). Or use the full path wherever a command is expected, for example `claude mcp add keyfold -- /Applications/Keyfold.app/Contents/MacOS/keyfold mcp`. Keyfold 1.0.0 didn't include it; update the app if `keyfold` isn't there.

## Command line

```
keyfold projects                                  # project and environment names
keyfold names -p acme -e production               # secret names only
keyfold env -p acme -e production                 # writes ./.env (add it to .gitignore)
keyfold env -p acme -e production --stdout        # prints instead
keyfold run -p acme -e production -- npm start    # injects secrets as environment variables
keyfold create-project acme -e development -e staging   # environments default to development, production
keyfold import -p acme -e development -f .env.local    # imports a .env file (default ./.env)
```

`keyfold run` starts the command directly, not through a shell, so `$VARS` in it are expanded by your shell before Keyfold injects anything; wrap the command in `sh -c '…'` when it needs the injected values itself.

If Keyfold is locked, the command says so; unlock the app and run it again. "Allow for 1 hour" in the approval sheet covers the same project and environment for that client, whatever command runs, so a `keyfold run` loop does not prompt every time.

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
| `keyfold_create_project` | Create a project with environments (default: development and production); safe to call twice | Project and environment names |
| `keyfold_import_env` | Import every `KEY=VALUE` line of a `.env` file into an environment; the MCP process reads the file, so values never pass through the model | Counts of keys added and updated |

There is deliberately no "reveal" tool. A prompt injection inside the agent cannot ask Keyfold for values; the worst it can do is run a command that prints them, and from 1.0.1 the approval sheet shows that command before anything runs. Under a one-hour grant later commands run without a new sheet, so keep your agent's own prompt on for `keyfold_run` too.

### The approval sheet

Each request shows the client name and process id, the action, whether it reads values, and, from 1.0.1, what the values are for: the command `keyfold_run` or `keyfold run` will start, the file `keyfold_write_env` or `keyfold env` will write, or that `keyfold env --stdout` will print them. Choices: Deny, Allow once, Allow for 1 hour (same client name, project and environment, whatever the command; every MCP client is named `keyfold-mcp`). Requests time out after three minutes if nobody answers. While Keyfold is locked it refuses every request, and locking ends every grant (from 1.0.1).

### Socket

macOS: `~/Library/Application Support/com.cwksolutions.keyfold/agent.sock`, mode 0600. Windows: named pipe `com.cwksolutions.keyfold.agent`. Only processes running as your user can reach it.
