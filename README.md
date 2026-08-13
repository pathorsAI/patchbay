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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the checks CI runs, the commit
message convention, and the two review rules that are not negotiable (probes
never touch token *values*; tests never read the real `$HOME`). Release history
is in [CHANGELOG.md](CHANGELOG.md).

## Status

Early. Building in the open. macOS first; probes are plain-file readers so Linux support is mostly path mapping.

MIT © Pathors AI
