# MCP client management


Every AI client on your machine keeps its MCP servers somewhere else, in its own
spelling. Registering one server everywhere means editing four files in two
formats and getting the field names right — `mcpServers` here, `servers` there,
`[mcp_servers.<name>]` in the TOML one, `serverUrl` in exactly one of them.

```sh
pb mcp list          # the matrix: every server × every client that has one
pb mcp list --json   # what the panel and the MCP server see
```

```
SERVER               claude-code  claude-desktop  cursor  codex
Framelink Figma MCP  —            —               ✓       —
figma                proj         —               —       —
grafana-pathors      ✓            —               —       —
node_repl            —            —               —       ✓
patchbay             ✓            —               —       —

claude-code — Claude Code
  ~/.claude.json
  grafana-pathors  stdio uvx (1 arg)  [user]
    env: GRAFANA_URL, GRAFANA_SERVICE_ACCOUNT_TOKEN
  figma  http https://mcp.figma.com/mcp  [project:/Users/you/repo]
```

Move one across instead of retyping it:

```sh
pb mcp copy patchbay --from claude-code --to cursor,codex
pb mcp add cursor patchbay --command /usr/local/bin/patchbay-mcp
pb mcp add work --url https://mcp.example.com/mcp --transport http
pb mcp rm cursor patchbay
```

`copy` reads the whole definition — command, arguments, URL, environment,
headers — and writes it in the target's own dialect, so a JSON `mcpServers`
entry becomes a `[mcp_servers.<name>]` TOML table and back.

| Client | Config | Shape |
|---|---|---|
| `claude-code` | `~/.claude.json` | `mcpServers` + `projects.<path>.mcpServers` |
| `claude-desktop` | `~/Library/Application Support/Claude/claude_desktop_config.json` | `mcpServers` |
| `cursor` | `~/.cursor/mcp.json` | `mcpServers` |
| `codex` | `~/.codex/config.toml` (or `$CODEX_HOME`) | `[mcp_servers.<name>]` |
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` | `mcpServers`, `serverUrl` |
| `vscode` | `~/Library/Application Support/Code/User/mcp.json` | `servers` |

### The rules it writes by

**Names, never values.** The board reports `env_keys` and `header_keys`, and a
count of a command's arguments — never the values. That is not squeamishness:
on a normal machine those exact fields hold `--figma-api-key=…`,
`GRAFANA_SERVICE_ACCOUNT_TOKEN` and `Authorization: Bearer …`. A `copy` does
carry the values (a server that cannot authenticate is not a server), and says
which ones travelled and into which file, so you can decide whether a token now
living in three places is fine.

**Backup, then atomic write.** Before any change the file is copied to
`<path>.patchbay-bak` — one rolling generation, the undo for the write about to
happen. The new content goes to a temp file in the same directory and is
renamed over the original, so a crash mid-write leaves the old file intact.

**Your file stays your file.** Writes are parse-modify-serialize, never a
rewrite from a template: unrelated top-level keys, other servers, JSON key
order and TOML comments all survive. Adding a server to a 7,000-line
`config.toml` is a four-line diff.

**User scope only.** Claude Code's per-project servers are read and labelled
`project:<path>`; they are never written. A project's servers are that
project's business.

**Clients read their config at startup.** Nothing you change here reaches a
running client, and Claude Code rewrites `~/.claude.json` when it exits —
restart it rather than expecting a live update.

**AI agents get the same board.** Over MCP: `list_mcp_clients` (metadata only),
`add_mcp_server`, `copy_mcp_server`, `remove_mcp_server`. These are not gated
the way the vault's tools are — they are config files, not secrets — but their
descriptions tell the agent to confirm before removing anything, to relay the
restart requirement, and never to inline a secret into an `env` or `headers`
block, because those land in a plain-text file. An agent that just set a server
up for you can now put it in every client you use.

