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
  --env CLOUDFLARE_API_TOKEN \
  --label "CF deploy token" \
  --purpose "deploy worker from GitHub Actions in pathorsAI/patchbay" \
  --scopes workers:edit,zone:read \
  --expires 2027-01-01

pb key list                 # id, provider, env, label, last4, expiry, purpose
pb key list --expiring 30   # what dies in the next month
pb key list --env CLOUDFLARE_API_TOKEN   # who holds the name code reads
pb key list --provider cloudflare        # everything from one issuer
pb key list --grep deploy                # id, label, purpose, provider, env
pb key list --json          # what the MCP server and the panel see
pb key edit cf-gh-actions-deploy --env CLOUDFLARE_API_TOKEN  # metadata only
pb key copy cf-gh-actions-deploy    # to the clipboard, never to your terminal
pb key run  cf-gh-actions-deploy -- wrangler deploy  # into a child process
pb key verify cf-gh-actions-deploy  # ask Cloudflare whether it still works
pb key rm  cf-gh-actions-deploy     # metadata and Keychain item, both
```

### In the panel

The vault view browses the same registry, and writes to it: **add key** opens a
form — id, env, provider, label, a masked secret field, and the optional
purpose, scopes, expiry and endpoint behind a fold — and each row has a trash
affordance with an inline confirm. Both go through the same `KeyRegistry` calls
as `pb key add` and `pb key rm`, so the rules and the error messages are
identical. The table shows the env name in its own column, next to the provider.

The panel takes a secret; it never gives one back. There is no reveal, no copy,
and no command behind the window that returns a value — the two ways out are
both in the CLI, `pb key copy <id>` and `pb key run <id> -- <cmd>`. See the
security model below for why the asymmetry survives a GUI intact.

### The second name: env

An entry's `id` is a lowercase slug: `cf-gh-actions-deploy`. The name code
reads is something else entirely: `CLOUDFLARE_API_TOKEN`. Nothing connected the
two. Whoever needed the token — a script, a CI job, an agent working in this
repo — had to already know that the Cloudflare token lives under an id built
out of "gh actions" and "deploy", which is not a thing you can guess and not a
thing you can search for. The mapping did exist, as prose, buried in a
`--purpose` string. Prose is not an index.

`--env` makes it a field:

```sh
pb key add cf-gh-actions-deploy --env CLOUDFLARE_API_TOKEN --provider cloudflare
pb key list --env CLOUDFLARE_API_TOKEN     # who holds it
pb key run  cf-gh-actions-deploy -- wrangler deploy   # use it under that name
```

The name is validated on the way in: A–Z, digits and `_`, starting with a
letter, at most 64 characters — the shape a shell and every dotenv parser will
actually accept. A refusal spells out the corrected name rather than restating
the rule, so `cf-token` comes back as "env names are UPPER_SNAKE_CASE (the shape
code reads them in); try `CF_TOKEN`" and the fix is a copy-paste.

It is **optional**, and deliberately so. An Apple issuer id or a D-U-N-S number
belongs in the vault as an index entry — something you will need and would
otherwise have to go looking for — but it is not a variable any program reads,
and inventing a name for it would be inventing a fact. Leave it off.

**Two entries may share a name.** A dev and a production `LANGFUSE_SECRET_KEY`
are two different secrets that code reads under one identifier; that is the
normal shape, not a conflict, so nothing refuses it and a lookup returns both.
The `id` stays unique and stays the thing you name in a command.

#### Naming convention

Use **the name code already reads**. If the repo, the CI secret or the vendor's
own SDK spells it `CLOUDFLARE_API_TOKEN`, that is the name — patchbay's job is
to be findable by what already exists, not to impose a taxonomy on it. Only
when nothing has named it yet do you compose one, as
`<PROVIDER>_<THING>_<KIND>`: who issued it, what it is, what kind of thing it
is.

| Name | Why |
|---|---|
| `CLOUDFLARE_API_TOKEN` | what wrangler and Cloudflare's own docs read |
| `NEON_API_KEY` | provider, then kind; nothing in between to say |
| `APPLE_ASC_ISSUER_ID` | provider, the thing (App Store Connect), the kind |
| `GITHUB_APP_PRIVATE_KEY` | the app's key, not the user's — `THING` disambiguates |
| `LANGFUSE_SECRET_KEY` | pairs with `LANGFUSE_PUBLIC_KEY`; the kind carries the difference |
| `R2_SECRET_ACCESS_KEY` | the S3-compatible name R2 clients already expect |

The kinds: `_API_KEY`, `_API_TOKEN`, `_SECRET`, `_SECRET_KEY`, `_PRIVATE_KEY`,
`_PASSWORD`, `_ID`, `_URL`.

#### Backfilling

Every key registered before this field existed has no name, and the vault is
worth exactly as much as the fraction of it that is findable. `pb key edit`
fixes that without going near the keychain:

```sh
pb key edit cf-gh-actions-deploy --env CLOUDFLARE_API_TOKEN
pb key edit neon-api --env NEON_API_KEY --purpose "prod branch migrations"
pb key edit old-thing --no-env
```

`edit` is metadata only — it never opens the keychain, never touches the
value, and cannot rotate anything. Rotation stays `pb key add --overwrite`,
where a secret is actually being handled. The flags mirror `add`'s —
`--provider`, `--label`, `--purpose`, `--scopes`, `--expires`, `--endpoint`,
`--env` — and the four nullable ones have a clearing form: `--no-purpose`,
`--no-expires`, `--no-endpoint`, `--no-env`. `id`, `last4` and the registration
date are not editable, because they describe the value in the keychain and
editing them here would only make the registry lie about it.

### Using a key without seeing it

A vault an agent cannot use is a vault an agent will work around. `pb key copy`
was the only way a value came out, and it goes to the clipboard — fine for a
human pasting into a browser, useless to a process, and not something an agent
should be doing at all.

```sh
pb key run cf-gh-actions-deploy -- wrangler deploy
pb key run neon-api langfuse-prod -- bun run migrate
pb key run --as CF_TOKEN=cf-gh-actions-deploy -- ./deploy.sh
```

`run` looks each id up, reads its value from the keychain, and starts the
command with those variables added to the environment it inherits. The value
goes keychain → child process and touches nothing else: not stdout, not a log,
not argv, not a file, and not the context of whatever model asked for it.
stderr names the variables and the ids it filled them from, so you can see what
was injected without seeing what was injected.

An id with no `env` name and no `--as` is refused, naming the id and the
`pb key edit <id> --env NAME` that fixes it — a run that silently dropped a
credential would fail somewhere much less obvious.

This is the second way a value leaves the vault, and the two are for different
people. `pb key copy` is for a human with a browser tab open. `pb key run` is
for everything else, and it is the path an agent should take: the answer to
"I need `CLOUDFLARE_API_TOKEN`" is a command to run, not a value to read.

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

**Writing is easy, reading is not.** There is no `pb key show`. Two commands
read a value and they are the only two. `pb key copy` pipes it into `pbcopy`;
`pb key run` puts it in one child process's environment. Neither passes it
through stdout, a log, argv or your shell history, and neither prints it.

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
| `store_key` | open — this is the point. An agent that creates a key registers it, with `env`, purpose and expiry, so your patchbay stays the source of truth |
| `list_keys` | open — metadata only, plus a derived `expiry_state`. Takes `provider`, `env` and `query` filters, so an agent narrows the vault instead of reading all of it |
| `update_key` | open — metadata only. It cannot reach the keychain and cannot rotate anything, so backfilling an `env` name or fixing a purpose needs no gate |
| `resolve_env_vars` | open — variable names in, names and commands out. Never a value |
| `verify_key` | open — a verdict carries nothing to leak |
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

**What the agent is told to do with all this.** A gate an agent never reaches
is not protecting anything, and for a long time that was the actual situation:
a vault with sixty-five keys in it, on a machine where the agent working in
your repo asked *you* for `CLOUDFLARE_API_TOKEN`, wrote a `<your-token-here>`
placeholder, or reported the variable as missing. It was not refused. It never
looked. So the server's instructions now carry two rules:

- **Look here before asking for a credential.** Before asking the human,
  writing a placeholder or calling something missing, call `resolve_env_vars`
  with the variable names the code reads. It answers per name: which vault
  entries carry that `env`, which env-vault projects define it, `suggestions`
  when nothing matches exactly (entries whose purpose, label or id mention the
  name or its distinctive words), a `status` — `key`, `project_var`, `both`,
  `suggested` or `missing` — and a `use` string: the exact `pb key run …` or
  `pb env run …` to put the value where the code will find it. It reads two
  local JSON files and returns **no secret value**, which is why it is
  ungated. The answer to "I need this credential" is a command, not a value.
- **Name the variable.** Register with `env` set, following the convention
  above, and backfill entries that lack one with `update_key`. An entry with no
  variable name is invisible to the lookup that would have found it, which is
  how a vault full of the right keys ends up being worked around.

**Known tradeoff.** The Keychain write shells out to `security
add-generic-password -w <value>`, which puts the secret in that command's argv
for the few milliseconds it runs — visible to `ps` for the same user. `security`
has no way to take a password on stdin. Moving to the Security framework API,
where the value never becomes a command line, is tracked in
`crates/patchbay-core/src/keystore.rs`.

**Removing is not revoking.** `pb key rm`, and the panel's trash affordance,
make patchbay forget a key. The credential keeps working until you revoke it at
the provider — which is what the panel's confirm says before it asks.

