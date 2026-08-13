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

> The release builds are **unsigned and un-notarized** — patchbay has no Apple
> Developer identity yet. macOS will refuse the first launch; right-click the
> app and choose *Open*, or run `xattr -dr com.apple.quarantine
> /Applications/patchbay.app`. Downloaded binaries need the same treatment.
> Building from source (below) avoids all of this.

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
