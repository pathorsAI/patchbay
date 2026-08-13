# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **kubectl** — a `~/.kube/config` that is a *directory* of per-cluster
  kubeconfigs (a common layout, and one kubectl itself chokes on) is now
  scanned instead of reported as zero contexts. The `*.yaml`/`*.yml` files
  directly inside it are merged first-file-wins, each context records the file
  it came from, files that are not kubeconfigs are skipped by name, and the
  note now spells out the `export KUBECONFIG=…` that makes a shell agree.
  Because every file carries its own `current-context`, no active context is
  reported unless exactly one file defines contexts.

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
