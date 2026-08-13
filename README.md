# patchbay

**One panel for every CLI login on your machine — built for humans *and* AI agents.**

Your dev machine is a tangle of authenticated CLIs: `gcloud` with five accounts, `gh`, `aws`, `az`, `infisical` across two orgs, `kubectl`, `wrangler`, `rclone`… Each one stores its auth state somewhere different, expires on its own schedule, and has its own switching incantation. Nothing shows you the whole board.

patchbay is the patch panel:

- **Status board** — every tool, every profile, which one is active, when its token expires. Read from local state files in milliseconds (the [starship](https://starship.rs) trick) — no API calls unless you ask to verify.
- **Permissions view** — see what your current tokens can actually do (`gh` token scopes, cloud IAM roles) and fix missing scopes with one action instead of re-generating tokens blind.
- **Switch** — change profile/context for any tool from the panel, including the traps (looking at you, `gcloud` ADC).
- **MCP server** — AI agents are first-class operators: `list_connections`, `switch_profile`, `get_permissions`, `verify`, `plan_setup`. "Switch to the cerana gcloud account and deploy" becomes one sentence.
- **Migrate** — export a bundle: portable credentials travel encrypted, device-bound ones (Keychain-backed `gh`, `infisical`) become a manifest entry. On the new machine, your AI reads the gap list and walks you through re-auth until the diff is zero.

## Layout

| Path | What |
|---|---|
| `crates/patchbay-core` | Probes (per-tool adapters), switch engine, permissions, manifest |
| `crates/patchbay-cli` | `pb` — status/switch/export in the terminal |
| `crates/patchbay-mcp` | MCP server (stdio) exposing the core to AI agents |
| `app` | Tauri 2 desktop app — the panel |

## Status

Early. Building in the open. macOS first; probes are plain-file readers so Linux support is mostly path mapping.

MIT © Pathors AI
