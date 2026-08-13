# patchbay

[![CI](https://github.com/pathorsAI/patchbay/actions/workflows/ci.yml/badge.svg)](https://github.com/pathorsAI/patchbay/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**One panel for every CLI login on your machine — built for humans _and_ AI agents.**

`gcloud` with five accounts, `gh`, `aws`, `az`, `infisical` across two orgs, `kubectl`, `wrangler`, `rclone`… every CLI stores its auth somewhere different, expires on its own schedule, and has its own switching incantation. patchbay reads them all from local state files in milliseconds and puts the whole board in one place — a desktop panel for you, an MCP server for your AI.

![patchbay panel](docs/img/patchbay-panel.png)

## Table of contents

- [What it does](#what-it-does)
- [Install](#install)
- [Use](#use)
- [Moving to a new machine](#moving-to-a-new-machine)
- [MCP — let your AI operate it](#mcp--let-your-ai-operate-it)
- [Showcase](#showcase)
- [Build from source](#build-from-source)
- [Docs](#docs)

## What it does

- **Status board** — every tool, every profile, which is active, when tokens expire. File reads only; no API calls unless you ask to `verify`.
- **Switch** — change profile/context from the panel, the CLI, or an AI — including the traps (`gcloud` ADC).
- **Permissions** — see what your tokens can actually do (`gh` scopes today) and fix missing scopes with one hint.
- **[MCP client management](docs/mcp-clients.md)** — every MCP server registered in Claude Code, Claude Desktop, Cursor, Codex, Windsurf and VS Code in one matrix; copy a server between clients without hand-editing four files in two formats.
- **[Key vault](docs/key-vault.md)** — standalone API keys no CLI tracks: values in the macOS Keychain, metadata on disk, provider-aware `pb key verify`, and AI registration over MCP.
- **[Migrate](docs/migration.md)** — export to a new machine; whatever can't travel, your AI walks you through re-authing.

## Install

macOS. From [Releases](https://github.com/pathorsAI/patchbay/releases) — all artifacts are Developer ID signed, the DMG is notarized:

```sh
# panel: download the .dmg, drag to Applications

# CLI + MCP server (Apple silicon; use x86_64-apple-darwin on Intel)
tag=v0.1.0; arch=aarch64-apple-darwin; tmp=$(mktemp -d)
curl -fsSL "https://github.com/pathorsAI/patchbay/releases/download/$tag/pb-$tag-$arch.tar.gz" | tar xz -C "$tmp"
sudo mv "$tmp/pb" /usr/local/bin/
```

## Use

```sh
pb status            # the whole board in your terminal
pb use gcloud work   # switch a profile
pb verify gh         # actually check a token against its API
pb key list          # your registered API keys
```

Or just open the panel: search with `/`, filter by category or connection state, click a card to operate that tool.

## Moving to a new machine

```sh
pb export                        # one encrypted .pbx: the logins that can travel
pb import patchbay-*.pbx         # --dry-run first; existing files are backed up
pb plan                          # what's left, with the exact command for each
```

Files that work anywhere get copied (`gcloud`, `aws`, `kubectl`, `wrangler`,
`rclone`, `npm`, `docker`, `ssh` config…). Credentials the OS keychain or the
device itself is holding can't, and patchbay says so instead of pretending —
each becomes one line with the command that fixes it. Your AI can work that list
over MCP (`plan_setup`, `mark_setup_done`), and patchbay re-probes after every
step rather than believing it.

Encrypted with a passphrase, refuses to be written into a cloud-sync folder, and
never copies a private key. **[Full details, and the per-tool portability
table →](docs/migration.md)**

## MCP — let your AI operate it

```json
{ "mcpServers": { "patchbay": { "command": "/usr/local/bin/patchbay-mcp" } } }
```

Your agent gets `list_connections`, `switch_profile`, `verify`, `get_permissions`, `store_key`, `plan_setup`, and friends — "switch to the work gcloud account and deploy" becomes one sentence, and a key your AI creates mid-task gets registered instead of rotting in a chat log. Reading secret values back is **off by default** (`PATCHBAY_ALLOW_SECRET_READ=1` to opt in).

## Showcase

| Filter the board | Operate a tool |
|---|---|
| ![sidebar filters](docs/img/patchbay-panel-filters.png) | ![detail view](docs/img/panel-detail.png) |

## Build from source

```sh
cargo test && cargo run -p patchbay-cli -- status   # Rust workspace: core, CLI, MCP
cd app && bun install && bun run tauri dev          # the panel (Tauri 2 + React)
```

## Docs

- [Moving to a new machine](docs/migration.md)
- [Key vault — security model](docs/key-vault.md)
- [MCP client management](docs/mcp-clients.md)
- [Contributing & development](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

MIT © [Pathors AI](https://github.com/pathorsAI)
