# Project env vault


The key vault holds credentials that belong to a person or a machine. This
holds the other half of the same problem: the twenty variables a *directory*
needs before it will boot — `DATABASE_URL`, the provider keys, the feature
flags. Today they live in a `.env` file that is plaintext on disk, gitignored,
undocumented, and different on every laptop. The variables you deliberately
override for local work live in a second plaintext file next to it, and their
whole job is to never reach anyone else.

```sh
cd ~/repos/pathors
pb env init                          # register this directory as a project
pb env pull                          # fill the synced layer from Infisical
pbpaste | pb env set DATABASE_URL    # a local override; the value never touches argv
pb env diff                          # what this machine changes about `dev`
pb env run -- bun dev                # the merged environment, into one child process
```

Nothing there writes a file. The variable *names* go to
`~/.config/patchbay/projects.json`; the values go to the macOS Keychain.

### A project is a directory

`pb env init` registers the current directory under a slug — the directory's
own name unless `--id` says otherwise. Every later command resolves the project
from the cwd by walking up to the nearest registered root, so `pb env run`
inside `src/api/` finds the repo it belongs to. When two registered roots both
contain you — a service registered inside a monorepo that is also registered —
the deeper one wins, because it is the more specific answer.

The match is a plain path-prefix comparison with no symlink resolution. Making
it canonical would make the answer depend on the filesystem's mood, and `/tmp`
on macOS is itself a symlink. A checkout reached through a symlinked path
therefore will not match; pass `--project <id>` there.

Each project has named environments — `dev`, `staging`, `production`, whatever
you like — and a `default_env` used when a command does not say (`dev` unless
`--default-env` changed it). Project ids and environment names are lowercase
slugs of at most 64 characters: letters, digits, `-`, `_`, `.`. Variable names
must match `[A-Za-z_][A-Za-z0-9_]*`, because a name outside that set cannot be
`export`ed by a POSIX shell at all, and storing something no consumer could
ever read is not a favour.

An environment is created by the first write to it. Registering a project
creates no Keychain items at all.

### Two layers

Every environment has exactly two layers, and the split is the whole point.

| Layer | Written by | On the next `pull` | Ever leaves this machine |
|---|---|---|---|
| `synced` | `pb env pull` | replaced wholesale | it came from there |
| `local` | `pb env set`, `pb env import` | untouched | **no** |

On merge, **local wins**. These are `.env.local` semantics: pointing
`DATABASE_URL` at a container on your own laptop has to survive every pull, or
nobody will trust `pull` and everyone will go back to hand-edited files.

A pull replaces the synced layer wholesale rather than merging into it. That is
deliberate: a variable deleted upstream has to disappear here too, and a merge
would keep it forever.

**patchbay never pushes.** There is no code path in the crate that writes a
variable to a remote secret manager. A tool that can quietly promote a local
experiment into the team's shared `production` set is a tool nobody should run,
and a local override is invisible to the cloud by construction rather than by
policy. Changing a value upstream is the Infisical CLI's job, or the
dashboard's.

That has one consequence worth stating plainly. `pb env unset` removes a local
override and nothing else; a synced twin of the same name simply comes back
into effect, and the command says so:

```
`DATABASE_URL` is still set by the synced layer of `pathors/dev`; the pulled
value is in effect again
```

Asking it to remove a name that only exists in the synced layer is refused,
with the reason:

```
`API_KEY` in `pathors/dev` comes from the synced layer, so there is no local
override to remove; patchbay never pushes, so a pulled variable can only go
away by disappearing from the remote and being pulled again
```

`pb env list` and `pb env diff` answer from the two name lists alone — no
Keychain access, no prompt, no network. `list` labels each name `synced`,
`local` or `local override`; `diff` groups them the same way. Neither one has
ever seen a value.

### The account guard

The Infisical CLI's active user is machine-global: one field in
`~/.infisical/infisical-config.json`, shared by every shell, every project and
every agent on the box. So `infisical export` runs as whoever logged in last,
not as whoever the project belongs to — and when those differ, the API answers
403 with *"project does not belong to your selected organization"*, which reads
like a permissions problem with the project rather than the wrong login.

Each project's sync config therefore pins the account it belongs to.
`pb env pull` checks it **before** spending a subprocess:

```
`pathors` is linked to the infisical account `contact@pathors.com`, but
`someone.else@example.com` is the active login on this machine; the infisical
CLI has one active user for the whole machine, so switch first:
`pb use infisical contact@pathors.com`
```

Nothing runs and nothing is stored. If the guard is somehow satisfied and the
real 403 arrives anyway, patchbay recognises the phrase and appends the same
advice to Infisical's own message.

`pb env init` picks the pin up for you: it reads `.infisical.json` in the
directory for the `workspaceId` and records the currently active account
alongside it. `pb env link` sets or replaces the same thing by hand, and
`--map dev=development,production=prod` handles the projects whose remote spells
an environment differently — patchbay's name is what the vault records, the
remote's name is what goes on the command line. `--domain` is for self-hosted
and EU instances.

Two failure modes get their own answers rather than a stack trace: no login at
all points at `infisical login`, and a missing CLI points at `pb env import`,
since exporting by hand and importing is a perfectly good fallback.

A pull reports what it did in names and counts only — how many variables the
synced layer now holds, which local names shadow one, and notes for anything
odd. A remote name that is not a usable shell identifier is skipped with a
note rather than failing the pull: one strange key in a shared project must not
stop everybody else. A name the remote returned twice is noted too; the last
value won.

### Getting values out

Two commands read values, and they are the only two.

```sh
pb env run -- bun dev          # inject the merged environment into a child process
pb env export                  # dotenv on stdout, for redirection
pb env export --format json    # the same thing as an object
```

`pb env run` is the blessed path. The values go into one child process's
environment and touch nothing else — no file, no clipboard, no scrollback.
`pb env export` exists because sometimes a file is genuinely what you need
(a Docker `--env-file`, a CI step), and it writes to stdout so you decide where
that file lands; it warns when stdout is a terminal, because printing the whole
set into your scrollback is almost never what you meant.

Dotenv output is sorted, one `NAME='value'` per line. Single quotes, because
they are the only shell quoting with no escapes inside at all: an embedded `'`
closes the string, emits an escaped one and reopens it (`'\''`), and nothing
else in the value — `$`, backticks, backslashes, `#` — can mean anything. The
exception is a value containing a newline, tab or carriage return, which is
written double-quoted with those escaped as `\n`, `\t`, `\r`. A literal newline
inside single quotes is valid shell, but it would split the variable across two
lines and every line-based reader of a `.env` file would then read it wrong.
Output from `pb env export` parses back through `pb env import` unchanged.

### Coming from a .env file

```sh
pb env init
pb env import .env                 # into the local layer of the default environment
pb env import .env.production -e production
```

`import` merges into the **local** layer — never the synced one — because a
file on your disk is by definition not something the remote said. Everything
you import is therefore yours, stays yours, and survives the first pull.

The parser takes the dialect people actually write: `#` comments, blank lines,
an optional `export ` prefix, and values that are bare, single-quoted (literal)
or double-quoted with `\n`, `\t`, `\r`, `\"` and `\\` escapes. An escape
patchbay does not define is left exactly as written, so `"\d+"` stays `\d+`. In
a bare value, `#` is part of the value: `PASSWORD=hunter#2` is a password, not
a truncated one.

Every name is validated before anything is written, so an import is all or
nothing. Half an imported `.env` is worse than none, because the failure only
surfaces three commands later when something reads a variable that was never
stored. A malformed line is reported by **line number and nothing else** — the
text of a line patchbay failed to parse is, by definition, a string it does not
understand, and the likeliest thing it contains is a secret.

Once the values are in, delete the file. That is the point of the exercise.

### The commands

```
pb env init [--id <slug>] [--dir <path>] [--default-env <env>]
pb env link --project-id <uuid> [--project <slug>] [--account <email>]
            [--domain <url>] [--map dev=development,...]
pb env projects [--json]
pb env list   [-e <env>] [--project <id>] [--json]
pb env pull   [-e <env>] [--project <id>] [--json]
pb env set    NAME [-e <env>] [--project <id>]
pb env unset  NAME [-e <env>] [--project <id>]
pb env import <file> [-e <env>] [--project <id>]
pb env diff   [-e <env>] [--project <id>] [--json]
pb env run    [-e <env>] [--project <id>] -- <cmd> [args...]
pb env export [-e <env>] [--project <id>] [--format dotenv|json]
pb env forget [--project <id>] [--yes]
```

`pb env set` takes the value from stdin or a hidden prompt, never from argv —
the same rule as `pb key add`, for the same reason. `pb env forget` removes the
project from the registry and deletes every Keychain blob behind it, both
layers of every environment. It revokes nothing: a credential that was in there
keeps working until you rotate it at its provider.

### AI agents

| Tool | What it does | Gate |
|---|---|---|
| `list_env_projects` | registered projects, their roots, environments, sync config | open — metadata only |
| `list_env_vars` | names and provenance for one environment | open — metadata only |
| `pull_env` | refreshes the synced layer | open — it executes the Infisical CLI and hits the network, but the outcome it returns carries counts and names, no values |
| `set_env_var` | writes one variable into the local layer | open, like `store_key` — an agent that creates a project credential should register it, so the machine keeps knowing |

**No tool reads a value back.** Not gated behind `PATCHBAY_ALLOW_SECRET_READ`,
like the key vault's `get_key` — absent. An environment is dozens of values at
once, which makes it the single worst thing to hand an agent by accident, and
the two commands that do read values already exist in your terminal. If an
agent needs to run something with the project's environment, it should ask you
to run `pb env run`.

### The security model

**Two stores, split on purpose.** Values live in the macOS Keychain (service
`patchbay`), one item per project × environment × layer, under the account
`env:<project>/<env>/<synced|local>` — a whole layer as one compact JSON object,
so an export is one Keychain round trip rather than one per variable. The `env:`
prefix cannot collide with the key vault, whose ids are slugs and can never
contain `:` or `/`. Audit them with your own eyes:

```sh
security find-generic-password -s patchbay -a env:pathors/dev/local
```

Variable names, provenance and the last-pull timestamp go to
`~/.config/patchbay/projects.json`, mode `0600`, written atomically. Names are
not secret, but which of them a machine holds is nobody else's business.

**No last4.** The key vault records the last four characters of a value as a
recognition aid. Env vars get none, because half of these values are `true`,
`5432` or `postgres`, and four characters of a five-character value is not a
hint — it is the value.

**Both or neither.** A write puts the metadata down first and the Keychain item
second; if the Keychain refuses, the metadata file is restored byte-for-byte and
the error says so. The registry can never advertise a variable whose value was
never stored. `pb env forget` runs the same rule in reverse: if a Keychain
delete fails, the project is kept, because a registry entry whose values are
missing can be re-pulled, whereas a Keychain item nothing points at can only be
found by hand.

**A malformed registry is a hard error**, never an empty one. Starting over
silently would let the next write drop every project on the machine and orphan
every Keychain item behind them. So is a `projects.json` written by a newer
patchbay than the one you are running.

**Failures say nothing.** A failed `infisical export` is reported from its
stderr only — on a partial export or a broken pipe, stdout can already hold
secret material, and an error message is the one string guaranteed to be logged,
printed and pasted.

### Known tradeoffs

**The argv window.** The Keychain write shells out to `security
add-generic-password -w <value>`, which puts the layer's JSON blob in that
command's argv for the few milliseconds it runs — visible to `ps` for the same
user. `security` has no way to take a password on stdin. This is the same
tradeoff the key vault documents, and it is worse here in one respect: the blob
is the whole layer, not one secret. Moving to the Security framework API is
tracked in `crates/patchbay-core/src/keystore.rs`.

**`pb env export` re-materialises plaintext.** By your choice, at a moment you
picked, into a destination you named — but the vault's guarantee ends at the
redirect. `pb env run` gives up nothing, and is the reason `export` does not
have to be convenient.

**Symlinked checkouts need `--project`.** Directory resolution does not
canonicalize, deliberately (see above), so a path that reaches the repo through
a symlink is not recognised as inside it.

**One provider.** `infisical` is the only thing `pull` knows, and `pb env link`
refuses anything else by name rather than failing later. Everything else on the
machine arrives through `pb env import`.
