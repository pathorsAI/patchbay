# patchbay

[![CI](https://github.com/pathorsAI/patchbay/actions/workflows/ci.yml/badge.svg)](https://github.com/pathorsAI/patchbay/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**One panel for every CLI login on your machine — built for humans *and* AI agents.**

Your dev machine is a tangle of authenticated CLIs: `gcloud` with five accounts, `gh`, `aws`, `az`, `infisical` across two orgs, `kubectl`, `wrangler`, `rclone`… Each one stores its auth state somewhere different, expires on its own schedule, and has its own switching incantation. Nothing shows you the whole board.

patchbay is the patch panel:

- **Status board** — every tool, every profile, which one is active, when its token expires. Read from local state files in milliseconds (the [starship](https://starship.rs) trick) — no API calls unless you ask to verify.
- **Permissions view** — see what your current tokens can actually do (`gh` token scopes, cloud IAM roles) and fix missing scopes with one action instead of re-generating tokens blind.
- **Switch** — change profile/context for any tool from the panel, including the traps (looking at you, `gcloud` ADC).
- **MCP server** — AI agents are first-class operators: `list_connections`, `switch_profile`, `get_permissions`, `verify`, `plan_setup`. "Switch to the cerana gcloud account and deploy" becomes one sentence.
- **[MCP client management](#mcp-client-management)** — every MCP server registered in Claude Code, Claude Desktop, Cursor, Codex, Windsurf and VS Code, in one matrix. Copy a server from the client that has it into the ones that don't, formats translated, without hand-editing four files in two languages.
- **[Key vault](#key-vault)** — the standalone API keys no CLI tracks, in one registry. Values go to the Keychain, metadata to a file you can read, and an agent that just created a token registers it over MCP instead of leaving it to rot in a chat log.
- **Migrate** — export a bundle: portable credentials travel encrypted, device-bound ones (Keychain-backed `gh`, `infisical`) become a manifest entry. On the new machine, your AI reads the gap list and walks you through re-auth until the diff is zero.

## Install

macOS, from [Releases](https://github.com/pathorsAI/patchbay/releases). Every
tag ships per-arch tarballs of the two binaries plus a universal `.dmg` of the
panel.

The CLI and the MCP server — pick the tarball for your arch
(`aarch64-apple-darwin` for Apple silicon, `x86_64-apple-darwin` for Intel):

```sh
tag=v0.1.0
arch=aarch64-apple-darwin
tmp=$(mktemp -d)
curl -fsSL "https://github.com/pathorsAI/patchbay/releases/download/$tag/pb-$tag-$arch.tar.gz" | tar xz -C "$tmp"
sudo mv "$tmp/pb" /usr/local/bin/
pb status
```

Swap `pb` for `patchbay-mcp` to get the MCP server, then point your agent at it:

```json
{ "mcpServers": { "patchbay": { "command": "/usr/local/bin/patchbay-mcp" } } }
```

The panel: download `patchbay-<tag>-universal-apple-darwin.dmg` and drag it to
Applications.

Release builds are **signed with a Developer ID and notarized by Apple**, and
the notarization ticket is stapled to the `.dmg` — so it opens normally, with no
Gatekeeper warning, even on a machine that is offline. The `pb` and
`patchbay-mcp` binaries in the tarballs are Developer ID signed too (they are
not notarized: a loose executable has nothing to staple a ticket to, and
Gatekeeper does not quarantine-check a binary you extracted and ran from a
shell).

> The right-click → *Open* dance is only needed for **builds from before 0.1.0**
> and for **forks**, which build unsigned because they have no access to the
> signing secrets. For those: `xattr -dr com.apple.quarantine
> /Applications/patchbay.app`. Building from source is always unaffected.

Verify what you downloaded actually came from us:

```sh
spctl --assess --type open --context context:primary-signature -vv patchbay-*.dmg
codesign -dv --verbose=4 /usr/local/bin/pb 2>&1 | grep Authority
```

Each release also carries `SHA256SUMS-*.txt`; verify with `shasum -a 256 -c`.

## Layout

| Path | What |
|---|---|
| `crates/patchbay-core` | Probes (per-tool adapters), switch engine, permissions, manifest |
| `crates/patchbay-cli` | `pb` — status/switch/export in the terminal |
| `crates/patchbay-mcp` | MCP server (stdio) exposing the core to AI agents |
| `app` | Tauri 2 desktop app — the panel (React 19 + Vite front end, `app/src-tauri` Rust shell) |

The panel's board is one fixed-size card per tool; everything you can *do* to a
tool lives in its detail view. The sidebar slices the board by category and by
connection state — both derived in `patchbay-core`, so `pb --json` and the MCP
server report the same `category` and `connection_state` fields. `/` focuses
the search box, `Esc` clears the filters.

## Development

Rust workspace (core, CLI, MCP server):

```sh
cargo test          # unit tests for every probe
cargo run -p patchbay-cli -- status        # the board in your terminal
cargo run -p patchbay-cli -- status --json # what the app and the MCP server see
```

The panel. Needs [bun](https://bun.sh) and the Rust toolchain; `app/src-tauri`
is deliberately outside the root Cargo workspace, so it builds standalone:

```sh
cd app
bun install
bun run tauri dev     # panel + hot-reloading front end (vite on 127.0.0.1:1425)
bun run tauri build   # bundle a .app / .dmg
```

Front end only (no probes — `invoke` needs the Tauri shell, so the board shows
its error state):

```sh
cd app && bun run dev     # vite on 127.0.0.1:1425
cd app && bun run build   # typecheck + production bundle into app/dist
```

> A binary from a plain `cargo build` inside `app/src-tauri` still points at the
> Vite dev URL, so running it on its own opens a window with nothing in it. Use
> `bun run tauri dev`, or `bun run tauri build --debug` for a binary with the
> front end embedded. In debug builds the app prints the URL it loaded and
> whether the load finished, which is the first thing to check on a blank panel.

## MCP client management

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

## Key vault

The probes cover credentials some CLI already owns. The key vault covers the
ones nothing owns: the Cloudflare token you pasted into a GitHub Actions secret,
the provider key wired into a cron job, the service token an AI created for you
halfway through a task. They exist, they expire, and until now your machine had
no idea they were there.

```sh
# The secret is read from stdin, or from a hidden prompt. Never from argv.
pbpaste | pb key add cf-gh-actions-deploy \
  --provider cloudflare \
  --label "CF deploy token" \
  --purpose "deploy worker from GitHub Actions in pathorsAI/patchbay" \
  --scopes workers:edit,zone:read \
  --expires 2027-01-01

pb key list                 # id, provider, label, last4, expiry, purpose
pb key list --expiring 30   # what dies in the next month
pb key list --json          # what the MCP server and the panel see
pb key copy cf-gh-actions-deploy   # to the clipboard, never to your terminal
pb key rm  cf-gh-actions-deploy    # metadata and Keychain item, both
```

### The security model

**Two stores, split on purpose.** The secret goes into the macOS Keychain
(service `patchbay`, account = the key's id) and never touches patchbay's own
disk. The metadata — provider, label, purpose, scopes, expiry, source, and the
last 4 characters of the value — goes into `~/.config/patchbay/keys.json`,
mode `0600`. That file is readable, greppable and diffable, and worthless to
anyone who steals it. Audit the other half with your own eyes:

```sh
security find-generic-password -s patchbay -a cf-gh-actions-deploy
```

**Both or neither.** A write puts the metadata down first and the Keychain item
second; if the Keychain refuses, the metadata file is restored to exactly what
it was. The registry never advertises a key whose value was never stored.

**Writing is easy, reading is not.** There is no `pb key show`. `pb key copy`
pipes the value into `pbcopy` — it never passes through stdout, a log or your
shell history. Secrets never arrive as arguments either, in either direction.

**AI agents can register keys, not read them.** Over MCP:

| Tool | Gate |
|---|---|
| `store_key` | open — this is the point. An agent that creates a key registers it, with purpose and expiry, so your patchbay stays the source of truth |
| `list_keys` | open — metadata only, plus a derived `expiry_state` |
| `get_key` | **refused** unless the server process has `PATCHBAY_ALLOW_SECRET_READ=1` |
| `remove_key` | **refused** unless the same flag is set — it is destructive |

The flag lives on the server process, so only you can set it, and no argument
an agent sends can talk its way past it. The refusal says so and points the
human at `pb key copy <id>` instead. If you do want an agent reading values:

```json
{ "mcpServers": { "patchbay": {
    "command": "/usr/local/bin/patchbay-mcp",
    "env": { "PATCHBAY_ALLOW_SECRET_READ": "1" }
} } }
```

**Known tradeoff.** The Keychain write shells out to `security
add-generic-password -w <value>`, which puts the secret in that command's argv
for the few milliseconds it runs — visible to `ps` for the same user. `security`
has no way to take a password on stdin. Moving to the Security framework API,
where the value never becomes a command line, is tracked in
`crates/patchbay-core/src/keystore.rs`.

**Removing is not revoking.** `pb key rm` makes patchbay forget a key. The
credential keeps working until you revoke it at the provider.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the checks CI runs, the commit
message convention, and the two review rules that are not negotiable (probes
never touch token *values*; tests never read the real `$HOME`). Release history
is in [CHANGELOG.md](CHANGELOG.md).

## Status

Early. Building in the open. macOS first; probes are plain-file readers so Linux support is mostly path mapping.

MIT © Pathors AI
