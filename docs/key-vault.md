# Key vault


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
pb key copy cf-gh-actions-deploy    # to the clipboard, never to your terminal
pb key verify cf-gh-actions-deploy  # ask Cloudflare whether it still works
pb key rm  cf-gh-actions-deploy     # metadata and Keychain item, both
```

### In the panel

The vault view browses the same registry, and writes to it: **add key** opens a
form — id, provider, label, a masked secret field, and the optional purpose,
scopes, expiry and endpoint behind a fold — and each row has a trash affordance
with an inline confirm. Both go through the same `KeyRegistry` calls as `pb key
add` and `pb key rm`, so the rules and the error messages are identical.

The panel takes a secret; it never gives one back. There is no reveal, no copy,
and no command behind the window that returns a value — `pb key copy <id>` is
still the only way out. See the security model below for why the asymmetry
survives a GUI intact.

### Verification

`pb key list` can only repeat what you told it. `pb key verify` asks the issuer:

```console
$ pb key verify cf-gh-actions-deploy
cf-gh-actions-deploy (…4f0a) — valid
  This API Token is valid and active
  expires: in 141d (2027-01-01)
  updated the registry from the provider: expires_at
```

A successful check writes what the issuer said — expiry, and GitHub's scopes —
back into the registry, so the vault converges on the truth instead of drifting
from it. Every other provider answers `unsupported`, which is a normal answer
and not a failure.

| `--provider` | What patchbay asks | What comes back |
|---|---|---|
| `cloudflare` (`cf`) | `GET /client/v4/user/tokens/verify` | The token's own status — `active`, `expired` or `disabled` — plus `expires_on` when the token has one, and Cloudflare's own message. The endpoint reports liveness, not policies, so scopes stay empty: an account API token's *reach* is not something this call will tell you, which is exactly why it is worth registering next to `wrangler`. |
| `github` (`gh`) | `GET /user` | The login it authenticates as, the classic-PAT scope list from `X-OAuth-Scopes`, and the expiry from `github-authentication-token-expiration`. A fine-grained PAT sends an empty scope header — that is a real answer, not a missing one; its permissions are per-repository and not enumerable here. |
| `grafana` | `GET {endpoint}/api/org` | The org the token belongs to. **Needs `--endpoint`** — a Grafana token is only meaningful against the instance that issued it, and there is no one address to ask. Service-account tokens carry a role rather than a scope list, so scopes stay empty. |

```sh
pb key add grafana-pathors --provider grafana \
  --endpoint https://pathors.grafana.net \
  --label "Grafana service account (pathors)"
```

The endpoint must be the instance root, with no path. Point it at a dashboard
URL and Grafana Cloud answers `/api/org` with its single-page app — HTML, HTTP
200 — which patchbay reports as `unreachable` rather than reading a dead token
as live.

The verdicts are deliberately more than a boolean. `unreachable` (DNS, timeout,
rate limit, 5xx) means patchbay could not ask; it says **nothing** about the
key, and it never overwrites what you already had. Exit codes follow: `0`
verified or unsupported, `1` the provider says the key is dead, `2` the provider
could not be reached.

Agents get the same check over MCP as `verify_key`, and it is **not** gated
behind `PATCHBAY_ALLOW_SECRET_READ` — a verdict carries nothing to leak.

### Keys on the board

A key whose `provider` maps to a tool patchbay probes shows up on that tool's
row — `cloudflare` beside `wrangler`, `github` beside `gh`, `gcp`/`google`
beside `gcloud`, plus `aws`, `azure` and `infisical`. That is the point of the
vault for a machine that already has the CLI logged in: a Cloudflare API token
used for direct API calls is broader than wrangler's own OAuth session, and
nothing else on the machine knew it existed. The `wrangler` row says so when you
have one registered.

Providers with no CLI on the board — `grafana`, `openai`, `stripe`, anything
free-form — link to nothing and live in the vault view alone. That is not a gap;
there is no login for them to sit beside.

```console
$ pb status
TOOL       ACTIVE                PROFILES  EXPIRES        NOTES
wrangler   default               1         in 21d         +1 key · two wrangler configs exist
```

`+2 keys!` means one of them has expired or is about to. Unmapped providers
(`openai`, `stripe`, anything free-form) simply do not appear on the board.
`pb status --json` and the MCP `list_connections` carry the same thing as
`registered_keys`.

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
shell history.

**Why the CLI reads stdin.** A secret passed as an argument is not private:
argv is world-readable through `ps` for the length of the process, and your
shell writes the line verbatim into `~/.zsh_history`. So `pb key add` takes the
value from a pipe or a hidden prompt, never from a flag — in either direction.

**The panel takes a secret too, and that is not a hole in the rule.** The add
form's field is a password input; the value lives in memory for one call,
crosses the Tauri boundary once, and is handed to the same `KeyRegistry::add`
the CLI uses. No argv, no history file, no log — the two hazards the CLI rule
exists to avoid are properties of command lines, and a native window has
neither. What does not change is the other half: the panel never displays a
value, never copies one, and has no command wired up that could return one.
`KeyRegistry::get_secret` is deliberately not exposed to the webview.

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

**Removing is not revoking.** `pb key rm`, and the panel's trash affordance,
make patchbay forget a key. The credential keeps working until you revoke it at
the provider — which is what the panel's confirm says before it asks.

