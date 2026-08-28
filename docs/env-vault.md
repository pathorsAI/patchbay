# Project env vault


The key vault holds credentials that belong to a person or a machine. This
holds the other half of the same problem: the twenty variables a *repo*
needs before it will boot — `DATABASE_URL`, the provider keys, the feature
flags. Today they live in a `.env` file that is plaintext on disk, gitignored,
undocumented, and different on every laptop. The variables you deliberately
override for local work live in a second plaintext file next to it, and their
whole job is to never reach anyone else.

```sh
cd ~/repos/pathors
pb env init                          # register it, and leave a marker to commit
pb env pull                          # fill the synced layer from Infisical
pbpaste | pb env set DATABASE_URL    # a local override; the value never touches argv
pb env diff                          # what this machine changes about `dev`
pb env run -- bun dev                # the merged environment, into one child process
```

The only file any of that writes into the repo is the `.patchbay.toml` marker
`init` leaves for you to commit, and it holds a project name and nothing else.
The variable *names* go to `~/.config/patchbay/projects.json`; the values go to
the macOS Keychain.

### A project is a name, not a path

`~/.config/patchbay/projects.json` holds project ids, their environments and
where each one pulls from. It holds **no absolute path at all** — there is a
test that asserts exactly that — so it is the same file on every machine you
work from, and copying it is the supported way to take your projects with you.
Which directories on *this* machine belong to which project is a separate list,
`~/.config/patchbay/attachments.json`, because the same repo lives somewhere
else on the next laptop and a manifest that hard-codes `/Users/you/repos/x` is a
manifest that cannot travel. (One string in there does look like a path and is
not one: the [secret path](#which-folder-of-the-remote) names a folder *inside
Infisical*, is identical on every machine, and travels with the rest.)

A directory resolves to a project two ways, in this order:

1. **An attachment.** `pb env attach <id>` binds this directory to a project
   that already exists, on this machine only. The project whose attached root is
   the directory or an ancestor of it wins; when several match — a service
   attached inside an attached monorepo — the deepest root wins, because it is
   the more specific answer. `pb env detach` undoes it.
2. **A marker.** A `.patchbay.toml` committed at the repo root, holding one
   line that means anything: `project = "pathors"`. patchbay looks for it in the
   directory and then up through its ancestors, nearest first. `pb env init`
   writes it for you unless you pass `--no-marker`.

When neither answers, the command says so and names every way in rather than
guessing:

```
no project registered for this directory. Three ways in: `pb env init` here to
register a new project, `pb env attach <id>` to bind this directory to one that
already exists, or work in a checkout carrying a committed .patchbay.toml, which
resolves on its own. `pb env projects` lists what exists, and --project <id>
overrides all of it for one command
```

**An attachment always beats a marker.** An attachment is a deliberate, local
act: somebody stood in that directory and said which project it belongs to. A
marker is whatever the repo happens to ship. When the two disagree the person at
the keyboard wins, and nothing a repo can contain takes that override away.

A marker can only *name*. It points at a project the machine's own registry
already holds; it cannot define a sync config, an account, an environment or
anything else. One that names a project this machine does not have is a loud
error rather than a silent miss, because it is an explicit claim rather than
leftover state:

```
/repos/pathors/.patchbay.toml names project `pathors`, but this machine's
registry has no project `pathors`; copy your projects.json from the machine that
has it, or register it here with `pb env init --id pathors`
```

Git worktrees fall out of this for free: every worktree of a repo carries the
same committed marker, so all of them — and a second clone, and a colleague's
checkout — resolve to one project's environments with no setup at all.

The tradeoff is real and was taken deliberately: **repo content selects the
project**. Cloning a repository whose marker names `pathors` is enough to make
`pb env run` inject that project's variables in it. That is accepted on the
assumption that you run the repos you trust. Two things bound it — a marker can
only name a project you already registered, and an explicit attachment always
wins — so somebody who works from untrusted checkouts should pass `--no-marker`
and attach by hand instead.

### Taking it to a new machine

This is the whole point of the split. A new laptop is three steps:

```sh
pb import patchbay-*.pbx               # projects.json rides inside the bundle
git clone git@github.com:you/pathors   # the marker comes with the checkout
cd pathors && pb env pull              # rebuild the synced layer from Infisical
```

[`pb export`](migration.md#the-project-env-vault) carries the project manifest —
ids, environments and sync pins — so the migration bundle is the normal route.
Copying the file by hand still works and is the fallback when you are not moving
a whole machine:

```sh
cp projects.json ~/.config/patchbay/   # from the old machine
```

Either way, an id that already exists here is left alone: an import skips it
with a note rather than overwriting what may be the newer entry.

A checkout carrying a marker resolves on its own; anything else takes one
`pb env attach <id>`. Attachments deliberately do not travel — they are paths
from a machine that is not this one — so `attachments.json` is excluded from
every migration, copy and export story patchbay has. A project that arrived in a
bundle or a copied `projects.json` and has no attachment here shows `—` under
ROOTS in `pb env projects`, which is normal, not broken.

The **local layer deliberately does not travel either**. `.env.local` semantics
are per-machine overrides, and a `DATABASE_URL` pointing at a container on the
old laptop is exactly the thing that must not follow you. What the remote holds
comes back with `pb env pull`; what you set by hand you set again, on purpose.
Not even its variable *names* are carried, in a bundle or in a copied
`projects.json`: a name with no value behind it would make `pb env list` on the
new machine promise something `pb env run` could not deliver.

### Environments and names

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

`pb env init` picks the pin up for you when it registers a *new* project: it
reads `.infisical.json` in the directory for the `workspaceId` and records the
currently active account alongside it. That file names a workspace and never a
folder inside one, so an adopted link always starts at the root; `pb env link
--path` is how it learns better. An `init` that only attaches a second
worktree to a project that already exists reads nothing — that project's link is
already decided, and re-reading this checkout's file could silently replace an
env map somebody set by hand. `pb env link` sets or replaces the same thing
deliberately, and `--map dev=development,production=prod` handles the projects
whose remote spells an environment differently — patchbay's name is what the
vault records, the remote's name is what goes on the command line. `--domain` is
for self-hosted and EU instances.

Two failure modes get their own answers rather than a stack trace: no login at
all points at `infisical login`, and a missing CLI points at `pb env import`,
since exporting by hand and importing is a perfectly good fallback.

A pull reports what it did in names and counts only — how many variables the
synced layer now holds, which local names shadow one, and notes for anything
odd. A remote name that is not a usable shell identifier is skipped with a
note rather than failing the pull: one strange key in a shared project must not
stop everybody else. A name the remote returned twice is noted too; the last
value won.

### Which folder of the remote

Infisical's secrets are a **tree**, not a flat set. One project routinely holds
a folder per service — `/outbox`, `/worker`, `/web` — and a pull that reads the
wrong one does not fail. It succeeds, returns nothing, and reports `0 variables`
with a completely straight face, which is indistinguishable from a project
nobody has put anything in yet. `pathorsAI/coldmail` is the case that forced
this: everything it needs lives under `/outbox`, so until patchbay could be told
that, the repo could not use the env vault at all and fell back to
`infisical run --path /outbox -- <cmd>` by hand.

So each project's sync config pins a **secret path** alongside the account:

```sh
pb env link --project-id 3ab516bd-… --path /outbox
```

The default is `/`, the project's root, which is what every registry written
before the field existed meant and what every pull did. The spelling is
normalised on the way in — `outbox`, `/outbox/` and `/outbox` are one folder,
stored once as `/outbox` — so two links to the same place cannot produce two
entries that look different in `pb env projects` while pulling the same
secrets. An empty `--path ""` means the root, because somebody who passes it
means "no subfolder" rather than "a folder with no name".

`pb env link` replaces the whole sync config, exactly as it does for `--domain`
and `--map`: re-linking without `--path` puts the project back on `/`. And the
path is only passed to the CLI when it is *not* `/` — `infisical export`
already defaults to the root, so sending `--path /` would change no result while
narrowing the CLI versions patchbay runs under.

Where you see it: `pb env link` and `pb env init` echo a `secret path:` line,
`pb env projects` shows a non-root path in the SYNC column (`/` is left off,
since a column saying the same thing on every row is noise), and every pull
reports the folder it read. A pull that comes back empty says which folder was
empty and names the command that repoints it.

**This is not a filesystem path**, and it is not an exception to *A project is a
name, not a path* above. That rule is about directories on **this machine**:
`projects.json` records no `/Users/you/repos/x`, because a manifest holding one
cannot travel to the next laptop — which is why the roots live in
`attachments.json` instead. A secret path is a coordinate **inside the remote**.
It is the same string for every teammate on every machine, exactly as portable
as the Infisical project id sitting next to it, and it belongs in the file you
copy. Two slash-separated strings, two entirely different lifetimes.

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
pb env init   [--id <slug>] [--dir <path>] [--default-env <env>] [--no-marker]
pb env attach <id> [--dir <path>]
pb env detach [--dir <path>]
pb env link --project-id <uuid> [--project <slug>] [--account <email>]
            [--path /outbox] [--domain <url>] [--map dev=development,...]
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

`pb env init` does three things: register the project (under `--id`, else the
name the directory's own marker claims, else the directory name as a slug),
attach this directory to it, and write the marker. Run in a worktree or a second
clone of a project this machine already knows, it attaches that directory
instead of failing on the duplicate id. Run in a fresh clone whose marker names
a project the registry lacks, it registers the project the repo names — which is
the case that makes `git clone && pb env init` work on a machine you have not
copied `projects.json` to yet. An `--id` that disagrees with a marker already in
the directory is refused before anything is registered, since that is a
directory being pulled in two directions; `--no-marker` is the way through, and
the attachment it makes beats the marker anyway.

`pb env projects --json` prints the portable manifest's own shape and nothing
else: this machine's attachments live in another file for a reason, and folding
them in would produce JSON that cannot be copied to the next laptop. The plain
table folds them into a ROOTS column, and names any attachment whose project is
not registered here in a footer, since that is the one thing a column cannot
show.

`pb env set` takes the value from stdin or a hidden prompt, never from argv —
the same rule as `pb key add`, for the same reason. `pb env forget` removes the
project from the registry, drops this machine's attachments to it, and deletes
every Keychain blob behind it, both layers of every environment. It revokes
nothing: a credential that was in there keeps working until you rotate it at its
provider. It also touches no repository — a committed marker is left exactly
where it is, and the command says so:

```
  a committed .patchbay.toml is untouched: run `rm .patchbay.toml` in the repo
  if it should stop claiming `pathors`
```

### AI agents

| Tool | What it does | Gate |
|---|---|---|
| `list_env_projects` | registered projects, their environments and sync config, plus this machine's attached `roots` | open — metadata only |
| `list_env_vars` | names and provenance for one environment | open — metadata only |
| `pull_env` | refreshes the synced layer | open — it executes the Infisical CLI and hits the network, but the outcome it returns carries counts and names, no values |
| `set_env_var` | writes one variable into the local layer | open, like `store_key` — an agent that creates a project credential should register it, so the machine keeps knowing |

`roots` there is this machine's attachments and not the project's home, which
the tool's own description spells out: an empty list is the normal state for a
project resolved by its marker, or one that arrived in a copied `projects.json`,
so a path in that field is never proof of where you are working.

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
`~/.config/patchbay/projects.json`, mode `0600`, written atomically. Which
directories on this machine map to which project go to `attachments.json`, the
same way. Names are not secret and neither is a directory path, but which of
them a machine holds is nobody else's business.

The `.patchbay.toml` marker is the one file that gets none of that treatment: it
is written with ordinary permissions, because it holds a project *name*, it is
meant to be committed, and a `0600` file in a repo would only confuse the next
person to `ls -l` it. Re-pointing an existing marker at a different project is
refused — that changes what every checkout of the repo resolves to, so it should
be a deliberate edit, not the side effect of running a command in the wrong
directory.

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
patchbay than the one you are running. `attachments.json` follows the same
discipline — missing is empty, malformed names the file, a newer version is
refused rather than rewritten — and carries its own schema version, because the
two files have different lifetimes: one is copied between machines, the other is
rebuilt on each.

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

**A committed marker means repo content selects the project.** Stated in full
above: cloning a repo whose `.patchbay.toml` names `pathors` makes that
project's variables available in it. The bounds are that a marker can only name
a project you already registered, and that an attachment always overrides it.
`pb env init --no-marker` plus `pb env attach` is the way to work from checkouts
you do not trust.

**Symlinked paths do not match an attachment.** Roots are compared by plain path
prefix with no canonicalization, deliberately: resolving symlinks would make the
answer depend on the filesystem's mood, and `/tmp` on macOS is itself a symlink.
A checkout reached through a symlinked path is therefore not recognised as
inside its attached root — commit a marker, which is found by walking up
whatever path you actually used, or pass `--project <id>`. The same exactness
applies to `pb env detach`: it matches the root as it was recorded, so
`/tmp/work` and `/private/tmp/work` are two different roots, and detaching needs
the spelling that attached.

**One provider.** `infisical` is the only thing `pull` knows, and `pb env link`
refuses anything else by name rather than failing later. Everything else on the
machine arrives through `pb env import`. The secret path is stored as the string
you gave it and is never checked against the remote: patchbay cannot tell a
folder that is empty from one that does not exist, because the CLI answers both
with an empty export and a zero exit code. What it can do is say which folder it
read, and it does, on every pull.
