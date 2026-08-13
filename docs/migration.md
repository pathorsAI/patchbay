# Moving to a new machine

Half of a developer's logins are plain files that would work anywhere. The other
half are in the OS keychain, in a device-registered session, or in a key that
*is* the machine's identity — and copying those either does nothing or does
something worse than nothing.

So patchbay does not pretend either half is the whole story. `pb export` moves
what can move, refuses to fake the rest, and hands you (or your AI) a checklist
with the exact command for every gap.

```sh
# old machine
pb export                       # -> patchbay-2026-08-13.pbx, encrypted

# copy it across by AirDrop / USB / LAN — not by cloud sync

# new machine
pb import patchbay-2026-08-13.pbx --dry-run
pb import patchbay-2026-08-13.pbx
pb plan                         # what is left
```

## What is in a bundle

One encrypted file, four parts:

1. **Portable credential files**, copied verbatim.
2. **Key vault secrets** — only with `--keys`. Off by default.
3. **`manifest.json`** — no secrets: profiles, active identities, `gh` scopes,
   key metadata, MCP registrations by name, and the gap list.
4. **`SETUP.md`** — generated at export time, including how to install patchbay
   on a machine that does not have it yet.

Parts 3 and 4 live *inside* the encrypted payload and are written out on import.

## The portability table

Every tool on the board declares its own policy in
[`migrate/policy.rs`](../crates/patchbay-core/src/migrate/policy.rs), with the
reason next to it. A probe added without a policy fails the build's
`test_every_registered_tool_has_a_policy`.

### Portable — the files travel

| tool | what moves |
|---|---|
| `gcloud` | `credentials.db`, `access_tokens.db`, ADC, `active_config`, `configurations/`, `legacy_credentials/` |
| `aws` | `config`, `credentials`, and the SSO token cache |
| `wrangler` | the OAuth config TOML |
| `rclone` | `rclone.conf` |
| `kubectl` | every file `KUBECONFIG` names |
| `vercel` | `auth.json` + `config.json` |
| `firebase` | the `configstore` login |
| `neon` | `credentials.json` |
| `doctl` | `config.yaml` |
| `flyctl` | `config.yml` |
| `npm` | `~/.npmrc` |
| `ssh` | **`~/.ssh/config` only** — never a private key |
| `docker` | the registry list; helper-held secrets stay in the keychain |
| `ngrok` | `ngrok.yml` (the authtoken) |
| `cloudflared` | `cert.pem` + the per-tunnel credential JSONs — account credentials, so encrypted payload only, never named in the manifest |

### Device-bound — nothing to copy

| tool | why | fix |
|---|---|---|
| `gh` | OAuth token in the OS keychain | `gh auth login` |
| `az` | MSAL cache is keychain-backed | `az login` |
| `infisical` | JWT lives in the vault backend | `infisical login` |
| `op` | 1Password registers the *device*; biometric unlock | `op account add` |
| `supabase` | token in the OS keyring | `supabase login` |
| `stripe` | live key is redacted on disk, real one in the keychain | `stripe login` |
| `tailscale` | the node key *is* this device on the tailnet | `tailscale up` |
| `claude` | OAuth token in the Keychain | `claude`, then `/login` |
| `ollama` | the credential is a private ed25519 key | `ollama signin` |

### Pointer-only

| tool | why | fix |
|---|---|---|
| `huggingface` | the token is a bare secret in a *cache* dir, and which named token is active cannot be read from disk | `hf auth login` |

## Security

- **Encryption** is `age` with a passphrase (scrypt recipient) — no key files to
  manage or lose. Prompted twice on export, hidden, never taken as an argument:
  argv is visible to `ps` and lands in your shell history.
- **The bundle is `0600`** and starts with a 19-byte cleartext header
  (`patchbay-bundle/1`) so a version skew is refused before you type a
  passphrase. Nothing else about it is readable.
- **Cloud-sync folders are refused.** Writing into iCloud Drive, Dropbox, Google
  Drive, OneDrive, Box or pCloud needs `--force`, because copying credential
  files is not a metaphor for how sessions get hijacked — it is the technique,
  and a bundle in a sync folder is that technique performed on yourself with a
  delivery mechanism attached. Move it by AirDrop, USB or a direct LAN copy, and
  delete it from both machines afterwards.
- **No secret leaves the encrypted payload.** Not into `manifest.json`, not into
  `SETUP.md`, not into a log line, an error, a `--json` blob or an MCP response.
  The types that hold credential material have hand-written `Debug` impls that
  print counts, so a stray `{:?}` cannot leak one.
- **Decryption is in memory only.** No staging directory: each file goes from
  the decrypted payload to its destination through a temp file *in the
  destination directory*, renamed into place.
- **Private keys never travel.** `~/.ssh/id_*` is not collected, by policy and
  by test.

## Import safety

- Existing files are copied to `<path>.patchbay-bak` before being replaced.
- `--dry-run` prints the whole plan and writes nothing at all, backups included.
- **Idempotent**: a destination whose bytes already match is left alone — no
  write, no backup, reported as `unchanged`. Running the import twice produces
  the same machine.
- Every path is resolved through `Paths` on the *destination*, so an
  `AWS_SHARED_CREDENTIALS_FILE` or a `[paths]` entry on the new machine decides
  where a file lands.
- Several kubeconfigs land in one directory, with a note telling you the
  `KUBECONFIG` line to set — kubectl only merges what the variable names.

## The AI-guided half

`pb plan` is the same list your agent gets over MCP:

- **`plan_setup(manifest_path?)`** — re-probes every tool and returns
  `{ open, done, blocked, complete, items }`. Each item carries `auto` (can
  patchbay close it itself?), the exact `command`, and `needs_browser`.
- **`mark_setup_done(item_id)`** — re-probes that one tool and reports whether
  the gap actually closed. It does not believe the agent, and it does not
  believe the user.

The rule the tool descriptions give an agent: work the list one item at a time,
run only what `auto` allows, hand every `needs_browser` item to the human with
the exact command, re-check after each one, stop when `complete` is true.

Without a manifest, `plan_setup` and `pb plan` still work — the list becomes
"what on this machine is not logged in".

`pb status --diff <manifest.json>` is the same comparison in board form.

## Notes

- **MCP registrations travel with their values.** A server nobody can
  authenticate to is not a server — the same trade `pb mcp copy` already makes.
  The manifest lists only the variable *names*, and the export prints them, so
  nothing travels unannounced. Project-scoped Claude Code servers are read but
  never carried: they belong to a repository, not to the machine.
- **`--keys` is opt-in per key.** `--keys` alone takes every vault secret,
  `--keys=a,b` takes those two. Without it, metadata still travels and each key
  becomes a checklist item with its provider and last four characters.
- **`pb plan` exits 1 while anything is open**, so `pb plan && ./deploy` does
  the obvious thing.
