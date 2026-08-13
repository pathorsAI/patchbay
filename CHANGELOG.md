# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **MCP client management** — one board for the MCP servers registered across
  the AI clients on this machine: Claude Code (`~/.claude.json`, user and
  project scopes), Claude Desktop, Cursor, Codex CLI (`config.toml`), Windsurf
  and VS Code. `patchbay_core::mcp_clients` reads all six formats into one
  model and writes three of the operations back.
- **`pb mcp`** — `pb mcp list` (the server × client matrix, or `--json`),
  `pb mcp add <client> <name>`, `pb mcp copy <name> --from … --to …` (translates
  between the JSON and TOML dialects), `pb mcp rm <client> <name>`.
- **MCP tools** — `list_mcp_clients`, `add_mcp_server`, `copy_mcp_server`,
  `remove_mcp_server`, so an agent that just set a server up can register it in
  every client the user has.
- Write safety for other tools' config files: a rolling `<path>.patchbay-bak`
  backup before every change, atomic temp-file-and-rename writes, and
  parse-modify-serialize so unknown keys, JSON key order and TOML comments all
  survive. Claude Code's project scopes are read and labelled but never written.
- The board reports `env_keys`, `header_keys` and an argument *count* — never
  values, since those fields routinely hold API keys. A `copy` does carry values
  (a server that cannot authenticate is useless) and names what travelled.

## [0.1.0] - 2026-08-13

First public cut. macOS only, and deliberately narrow: read local state, report
it accurately, and never touch a secret value.

### Added

- **`patchbay-core`** — the probe model. Each supported tool has an adapter
  that parses that tool's own on-disk state (INI, YAML, TOML, JSON, SQLite) and
  reports profiles, which one is active, expiry, and caveats. Tier-1 reads are
  file-only and take milliseconds; anything that shells out or reaches the
  network is a separate, explicitly-requested tier-2 call.
- **Probes for 8 tools** — `gcloud`, `aws`, `gh`, `infisical`, `kubectl`,
  `wrangler`, `rclone`, `az`. Each reports profiles and active profile; where
  the tool's state file says so, also token expiry and granted scopes.
- **`pb` CLI** — `pb status` (the board, as a table or `--json`), `pb use <tool>
  <profile>` (switch the active profile), `pb verify <tool>` (prove the active
  credential still works), `pb perms <tool>` (what the active credential is
  allowed to do).
- **`patchbay-mcp`** — an MCP stdio server over `rmcp`, exposing
  `list_connections`, `get_status`, `switch_profile`, `verify` and
  `get_permissions`, with tool descriptions that tell an agent which calls are
  cheap, which are expensive, and which mutate machine-global state.
- **Desktop panel** — a Tauri 2 app (React 19 + Vite) with the status board,
  per-tool detail, switch, verify and permissions views.
- **App icon** — patch-panel mark, full icon set for every bundle target.

### Security

- Probes report *metadata about* credentials only. Token, secret and passphrase
  values are never copied into a status struct, never logged, and never
  included in error messages — probes parse the fields they need (expiry,
  scopes, account) and drop the rest.
- Release artifacts are signed with a Developer ID Application identity. The
  `.dmg` is notarized by Apple with the notarization ticket stapled to it, so it
  verifies locally and opens without a Gatekeeper prompt even offline; the `pb`
  and `patchbay-mcp` binaries are signed with a secure timestamp and the
  hardened runtime. Forks build unsigned — they have no access to the signing
  secrets — and that path is kept working on purpose.

[Unreleased]: https://github.com/pathorsAI/patchbay/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pathorsAI/patchbay/releases/tag/v0.1.0
