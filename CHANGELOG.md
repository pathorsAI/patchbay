# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`pb manifest` — the record of what this machine uses, with no credential in
  it.** `manifest.json` already existed and already had the right shape: no
  secret by construction, and the thing `pb plan --manifest` plans against. But
  it only ever existed *inside* an encrypted bundle, so getting the readable
  half meant producing the dangerous half first and then unpacking it. The one
  artifact that was safe to commit was the one you could not get without
  encrypting every credential on the machine.

  `pb manifest` writes it on its own, to stdout or `-o <file>`. It opens no
  credential file — not an optimisation, but the point: reading every
  credential to produce a file that will hold none of them is exactly the
  handling this command exists to avoid. The vault is listed and never
  unlocked, MCP servers are named with their env/header variable NAMES and
  never their values, and `carried` is empty everywhere because nothing was
  carried.

  Manifests now say which kind they are — `"kind": "inventory"` here,
  `"bundle"` inside an export, defaulting to `bundle` so an older file still
  reads. An inventory that claimed things had travelled would be the one lie
  this format must never tell.

  The intended shape: keep it in a repo you sync, and a new machine's whole
  setup is `pb plan --manifest setup/manifest.json` — install this, log into
  that — or the same list over MCP, worked one item at a time by an agent.

- **`write_manifest` MCP tool.** The one part of a machine move an agent can do
  unsupervised, because it touches no credential. `pb export` and `pb import`
  stay in the CLI, where the human and the passphrase are.

### Fixed

- **MCP records no longer claim to have been carried when they were not.**
  `collect_mcp` marked a registration `carried: true` whenever its spec was
  readable, which was true for a bundle and wrong for anything that does not
  carry values. Found while building the inventory path; it never affected a
  real export, where the two happened to coincide.

## [0.5.0] - 2026-08-28

### Added

- **`pb env pull` can read a folder inside an Infisical project, not just its
  root.** Infisical's secrets are a tree, and a project holding one folder per
  service is the ordinary shape — but patchbay had no idea such a thing
  existed and always exported from `/`. A pull aimed at the root of a project
  that keeps everything under `/outbox` does not fail: it succeeds, returns
  nothing, and reports `0 variables`, which reads exactly like a project nobody
  has filled in yet. `pathorsAI/coldmail` could therefore not use the env vault
  at all and ran `infisical run --path /outbox -- <cmd>` by hand.

  `pb env link --project-id <id> --path /outbox` now pins the folder alongside
  the account, `pb env pull` passes it to the CLI, and every place the sync
  config is visible says which folder it is: the `secret path:` line under
  `pb env link` and `pb env init`, the SYNC column of `pb env projects`, the
  `secret_path` field on a pull's result, and `sync.secret_path` in the MCP
  `list_env_projects`. A pull that comes back empty now names the folder it
  read and the command that repoints it, rather than leaving `0` to be
  interpreted.

  Nothing changes for a project that pulls from the root, which is still the
  default and still adds no flag to the `infisical` command line. Registries
  written by earlier versions have no such field and are read as `/`, so
  `projects.json` needs no migration and no version bump — the folder inside
  the remote is the same string on every machine, so it travels in the portable
  manifest exactly like the remote project id beside it.

## [0.4.1] - 2026-08-24

### Fixed

- **The panel no longer claims installed CLIs are "not available on PATH".**
  macOS launches GUI apps — and the MCP servers GUI clients spawn — with the
  bare launchd `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`), so the panel could
  not see a gcloud living in `~/google-cloud-sdk/bin` or a Homebrew-installed
  gh, and every tier-2 button answered "install it" for a tool that works
  fine in the terminal. The panel and `patchbay-mcp` now detect that bare
  inheritance at startup and adopt the login shell's `PATH` (asked of the
  user's own shell, with a hard timeout), so they resolve exactly the
  binaries a terminal would. Terminal launches are untouched: a `PATH` with
  any user entry on it is left alone.

## [0.4.0] - 2026-08-17

### Added

- **Nine CLIs patchbay refused to verify are now verified.** `wrangler`,
  `vercel`, `neon`, `supabase`, `flyctl`, `doctl`, `huggingface`, `stripe` and
  `firebase` used to answer `verify` with an excuse and a command to paste —
  "the CLI is node-based and slow to start", "that is a network call". Slow is
  not a reason: `verify` only runs when you press the button or type `pb
  verify`. Each now runs the tool's own check and reports the identity it
  answers with, so you can hold it against what the board claimed: the
  Cloudflare accounts behind a wrangler token, the Vercel username, the Neon
  account and plan, the Supabase projects and org, the Fly and DigitalOcean
  accounts, the Hub user and orgs, the Stripe account and key expiry, the
  firebase-tools accounts.

  Failures say one actionable sentence rather than pasting the tool's error
  paragraph, and they distinguish three states that used to be one: logged out,
  credential rejected, and *the network was unreachable* — the last of which is
  no longer reported as a bad login, because nothing about the credential was
  established. Where a check is local rather than a round trip (stripe and
  firebase have no read-only command that both names the account and exercises
  the credential) the answer says so instead of letting a tick imply more than
  it proved.

  Two hazards are handled rather than discovered later: `neon me` starts a
  browser login when there is no credential, so that state is answered from the
  tier-1 read without executing anything; and `fly auth whoami` offers an
  interactive login unless `--json` is passed, so it is.

- **kubectl, az and aws answer what a credential can do.** The scoped
  permissions seam gcloud opened is now filled by three more probes, and
  because the panel, `pb perms` and the MCP tools discover the capability from
  the probe rather than from a list, all three arrive with a picker and a
  reading and no wiring of their own.

  `kubectl` asks per namespace: the picker merges the namespaces the kubeconfig
  names with `kubectl get namespaces` when the cluster answers — the kubeconfig
  half matters because where `~/.kube/config` is a directory of per-cluster
  files, kubectl's own loader refuses it and patchbay's parse is the only thing
  that still has the list. The reading is `kubectl auth can-i --list`, tried in
  `-o json` and falling back to parsing the table for the versions that have no
  such flag, rendered as `get,list,watch pods`. `az` asks per subscription, and
  that list costs nothing: `azureProfile.json` already holds it, so unlike
  gcloud's the picker needs no grant to populate. Roles come from `az role
  assignment list --all --include-inherited`, and one granted on a single
  resource group is labelled `Contributor on resourceGroups/web` rather than
  being flattened into the subscription it is not held across.

  `aws` has no picker, because an AWS credential's permissions are not asked
  *about* anywhere — the identity is what it is. It resolves that identity
  through `sts:GetCallerIdentity`, which needs no permission, then reads the
  attached and inline policies. When that read is refused the report says so
  exactly: the identity is known, and listing its policies needs
  `iam:ListAttachedUserPolicies`, which is itself a permission most keys lack.
  An empty list would have read as "this credential can do nothing", which is
  the opposite of what is known. An SSO or assumed-role identity is named as
  the role it is instead of being asked a user-policy question it cannot
  answer.

  Every failure on these paths comes back as one actionable sentence. That is
  not cosmetic: a GKE context whose gcloud login has gone stale answers `auth
  can-i` with twenty lines of klog headers, a nested `config-helper`
  transcript, and gcloud's own four-line "Please run:" block, none of which is
  the answer.

### Changed

- **Notes carry a severity.** `ToolStatus.notes` was a `Vec<String>` — an
  untyped dumping ground that the panel rendered one way: every line behind the
  same amber warning triangle. So "docker has no active registry (normal for
  docker)" looked exactly like "credentials.db is unreadable", and a board of
  healthy tools read as a wall of complaints. Each note is now a `Note` with a
  `kind` of `info`, `warn` or `problem`. `info` draws no glyph and does not
  count towards the card's badge; `warn` keeps the amber triangle; `problem`
  gets a red one. `ToolStatus::note()` is gone, replaced by `info()`, `warn()`
  and `problem()` so the judgement has to be made at every call site.

  **Breaking JSON change.** `notes` in `pb --json`, in every MCP tool result,
  and on `PermissionsReport` and the MCP-client report, is now an array of
  `{"kind": "info"|"warn"|"problem", "text": "…"}` rather than an array of
  strings. There is deliberately no back-compat shim: a consumer that keeps
  treating notes as strings should fail loudly rather than print `[object
  Object]`.

- **Expiry carries its own state.** `expires_at: null` meant three unrelated
  things — this never expires, this expires but the timestamp is somewhere
  patchbay will not read, and this expires but the CLI renews it silently — and
  thirteen probes each wrote their own paragraph of prose explaining which one
  applied. `Profile.expiry` is now an `Expiry`: `at`, `no_expiry`,
  `unknown { reason }` or `refreshable { access_token_expires }`. The panel
  shows "no expiry", "expiry unknown" or "auto-renewed" accordingly, with the
  reason as the chip's tooltip, and only a real deadline takes a colour.

  `Profile.expires_at` is still in the JSON, unchanged in meaning: a timestamp
  for a real deadline, `null` for the other three. It is now *derived* from
  `expiry` rather than stored beside it, so the two can never disagree.

- **"This tool has no active X" is a property, not a note.** New
  `ToolStatus.active_concept`. rclone, npm, docker, ssh, stripe, flyctl, op and
  supabase say it once, in the type; the panel renders an em dash with the
  explanation as a tooltip instead of eight tools each filing a warning about
  working as designed.

- **patchbay's own execution switch no longer surfaces as a caveat about your
  login.** Five sites reported `command execution is disabled for this probe`
  as a user-facing reason. New `SwitchOutcome::ExecDisabled` /
  `VerifyOutcome::ExecDisabled` states instead: the panel greys the button and
  explains in a tooltip, and the CLI prints one short line.

- Notes that only restated something already on the row are gone: profile
  counts, tunnel-name counts, MCP-server counts, "AWS_PROFILE is not set, so
  the default profile is in effect" (inverted — it now speaks up only when the
  variable *is* set), and the neon config-directory trivia the advisory already
  covers.


- `infisical` still reports no permissions, but says why in one clause — its
  CLI has no command that reports a member's role — instead of sending you off
  to click around in a dashboard.

### Fixed

- **The panel was silently dropping every advisory.** Core has always
  serialized `advisories` on `ToolStatus` and the CLI has always rendered them,
  but the panel's TypeScript `ToolStatus` did not declare the field — so a tool
  that had been *removed* or abandoned looked identical to a healthy one. The
  drawer now has an advisories section above the notes, with the source link
  and a louder treatment for the blocking kinds.

- **A purely informational MCP message was wearing the red error banner.** The
  project-scope note in the MCP server drawer explains that patchbay declines
  to write another project's config — a deliberate boundary, not a failure. It
  now renders as a quiet notice.


## [0.3.4] - 2026-08-17

### Added

- **MCP servers can be added, edited, copied and removed from the panel.** The
  matrix could already show you that Cursor was missing the server Claude Code
  has, and then leave you to go and fix it somewhere else. A row now opens a
  drawer: the clients that have that server as chips, an editable form for the
  one you picked — transport, command and arguments or url, env vars, headers —
  a "copy here" beside every client that is missing it, and a remove. `+ add
  server` in the head opens the same drawer empty, with a checkbox per client
  to say where it should land.

  The form always shows exactly one client's copy and says whose, because that
  is the truth: six clients keep six files and Cursor's definition of a server
  can differ from Codex's, so a save writes one file rather than flattening the
  difference. Every write goes through the same core path the CLI uses, keeping
  the rolling backup, the parse–modify–serialize round trip and the atomic
  rename; the report says which file was written, where the backup is, and
  repeats core's caveats, the restart hint included. Saving is an explicit
  button — nothing autosaves, and closing a dirty drawer asks first. A Claude
  Code entry in a project scope is shown and explained rather than offered:
  patchbay does not write that scope, and now says so where you would try.

  The value boundary the matrix was built on is unchanged. `mcp_list`, which
  fills the table and refreshes after every write, still reports env var and
  header *names* and a count of arguments. Values are read by one new command,
  for one named server of one named client, because you opened its drawer —
  and a copy still reports which values travelled between files by name.

- **gcloud permissions are read, not described.** `permissions` for gcloud used
  to answer "IAM roles are per-project and per-resource; patchbay does not
  resolve them yet" and hand back a `gcloud projects get-iam-policy` line to
  paste — a bare command where an action would have worked, which is the one
  thing CONTRIBUTING says the panel does not do. It now runs the read itself
  and reports the account's roles on the project.

  That needed a shape the report did not have, because IAM grants live on the
  resource: a Google account has no roles of its own, only roles *on a
  project*. So permissions became optionally scoped, following `verify_profile`
  exactly. `Probe` gains `permission_scopes()` and `permissions_in(scope)`,
  both defaulted, so the other 24 probes are untouched and gh and wrangler
  behave as before; `PermissionsReport` gains `scope`, omitted from JSON when
  there is none. The panel shows a searchable project picker (type to filter,
  arrows and enter to choose, the configured project preselected) that appears
  only once the backend says the tool has scopes — listing them execs gcloud,
  so nothing runs until you press the button. `pb perms` gains `--scope` and
  `--list-scopes`; the MCP `get_permissions` gains an optional `scope`, beside
  a new `list_permission_scopes` tool.

  Two things that stayed deliberate. The unscoped read resolves the active
  configuration's `core/project` and reads *that*, the same move `verify` makes
  with the active profile, rather than answering a question it could work out
  for itself. And the copyable line survives in exactly one place — when there
  is no gcloud on `PATH` to run, so patchbay genuinely cannot answer.

- The frontend's hardcoded `PERMISSIONS_TOOLS` set is gone. Which tools can
  report permissions is the backend's fact, answered by `supported`, not a list
  in the UI that goes stale the moment a probe learns a new trick.

### Fixed

- **The main pane no longer scrolls sideways.** 0.3.3 stopped the *window*
  sliding as one sheet but left the board scrolling in both axes, so reaching
  the last client column of the MCP matrix dragged the view's title, its notes
  and its "Config paths" list off to the left with it — everything you needed
  as a reference left the screen at the moment you needed it. The board now
  scrolls down only; the tables scroll inside their own frame, which is what
  that frame was always for. Errors wrap instead of running off the edge, since
  a clipped error is worse than a wide one.

  The MCP table also stopped asking for width it never used: its floor was
  760px against the 686px of pane a 900px window gives, so the matrix scrolled
  even when it would have fitted. Six client columns of one glyph each carried
  10px of side padding around nothing; at 7px, and with the floor at 640px —
  the same as the vault's, and above the ~613px the headers themselves need —
  a typical matrix comes to 666px and fits the smallest window with room over.


## [0.3.3] - 2026-08-14

### Fixed

- **`wrangler` and `rclone` had the same borrowed-hour bug 0.3.2 fixed in three
  other probes**, and 0.3.2's sweep stopped at the probes that happened to be
  on the reporter's board. Both store an OAuth *access* token's expiry and both
  renew that token themselves — wrangler on the next command, rclone by
  refreshing and rewriting `rclone.conf` — so a live Cloudflare grant read
  "expired 154d" and Drive remotes read expired for as long as you had not used
  them. Each now keeps the timestamp only where nothing can renew it: wrangler
  when the config has no `refresh_token`, rclone when the remote's token blob
  has none. rclone learns that by reducing `refresh_token` to a bool at the
  point it reads the blob, so no part of the token outlives the parse.

  The full audit, so the next reader does not have to redo it: `aws` (SSO
  session — a real deadline, kept), `stripe` (`stripe login` keys expire and are
  not renewed, kept), `az` / `gh` / `claude` / `cloudflared` / `flyctl` (already
  reported unknown). `huggingface` stores `expires_at` beside an optional
  `refresh_token` and is the one case left unverified — see below.

- **The window no longer scrolls as one sheet.** `.body` carried `min-height: 0`
  but not `min-width: 0`, and as a grid item it therefore took its min-content
  width — which for a flex container is content-driven even when its children
  may shrink. One wide row of cards, or one long unbroken path in a note, sized
  that column past the window and took the header, the sidebar and the title
  bar scrolling sideways with it. Measured at a 420px viewport: the document
  was 506px wide. Containment is now structural — `html`/`body`/`#root` are
  `overflow: hidden`, `.body` is `min-width: 0` and hidden, and the board
  scrolls itself in both axes — so the chrome stays put and only the region you
  are reading moves.

### Changed

- **Opening a tool now verifies it.** Every profile in the drawer that has no
  verdict yet is checked on the way in, rather than showing a button and
  waiting to be asked a second time — the click that opened the drawer is the
  consent for the tier-2 call. Once per tool: a row that has been checked, or
  is being checked, is skipped, so the 30s board poll cannot turn it into a
  loop, and re-checking on demand is still the row's own button. The board
  itself stays tier 1 — file reads only, no network — because a status surface
  that shells out to twenty-five CLIs every thirty seconds is a different
  program.

## [0.3.2] - 2026-08-14

### Fixed

- **Verifying a profile now verifies *that* profile.** The panel's per-row
  check has always sent the profile id, and the Tauri command has always thrown
  it away and asked about whichever profile was active — so on a `gcloud` board
  with two configurations, pressing "verify" on the inactive one reported the
  active account's answer under the inactive one's row. Two rows, one truth,
  filed under both. The command now calls `Registry::verify_profile`, and
  `GcloudProbe` implements it: `gcloud auth print-access-token --account=<the
  account that configuration names>`, which is per-invocation and so never
  activates what it checks.

- **`gcloud` no longer reports a login as expired because its access token
  cache went stale.** `access_tokens.db` has a `token_expiry` column, and it is
  not the answer it looks like: it dates a one-hour OAuth access token that
  gcloud refreshes silently on the next call. Read as the profile's expiry it
  marked a working login "expired 3d" the moment you stopped using it for an
  afternoon, counted it in the board's expired tally, and — because a token
  minted *this second* is one hour out, well inside the 24h attention window —
  meant `gcloud` could never once read Connected. What actually ends a gcloud
  session is revocation or an org reauthentication policy, and neither is
  written to this machine, so the expiry is now `None` (unknown, as it is) with
  a note saying so and pointing at verify. `pb verify gcloud` is what answers
  the question that column was pretending to.

- **A failed `gcloud` check reads as one sentence instead of gcloud's error.**
  A reauth failure is four lines of shell instructions, which the panel joined
  into `…non-interactive execution.; Please run:; $ gcloud auth login; to
  obtain…`. Reauthentication, a revoked credential and a missing credential are
  now each named in a line that ends with the command that fixes it, for the
  account it is actually about; anything else keeps gcloud's own first line
  minus the prefix that only repeats what patchbay just ran. An account with no
  row in `credentials.db` is answered from tier 1 without spawning anything,
  and a `gcloud` that is not on `PATH` is `unsupported` rather than an error.

- **`gcloud`'s IAM hint is a command you can run.** It carried `<project>` and
  `<account>` placeholders while patchbay had both values on the row directly
  above, and its `--flatten=bindings[].members` was unquoted — a glob, which
  zsh answers with `no matches found` before gcloud ever starts. Now filled in,
  quoted, and the report names the account as its subject.

- **`firebase` and `neon` were dating the same borrowed hour.** Both stored an
  OAuth access token's expiry as the profile's, and both papered over it with a
  note — so the board read `firebase — expired 235d` and `neon — expired 12d`
  for two logins that work, and counted them in the expired tally on every
  refresh. Neither now reports an expiry it cannot stand behind, and both draw
  the line at the thing that actually decides it: `firebase` keeps the hour
  only for a grant with no `refresh_token` beside it (presence read through
  `serde::de::IgnoredAny`, so the value is still never held), and `neon` keeps
  it only for a grant without an `offline` scope, where the hour really is the
  whole login. The notes say what is unknown instead of apologising for what
  was shown.

- The permissions button no longer offers to "re-read scopes" for a tool
  patchbay has no scope reader for, where a second press cannot say anything
  the first did not.

## [0.3.1] - 2026-08-14

### Security

- **Every third-party action in CI and the release workflow is pinned to a full
  commit SHA**, with the tag it came from kept in a trailing comment. A moving
  tag is a standing invitation: whoever controls the action's repository can
  change what runs in a job that holds the Apple signing certificate. One trap
  worth recording, because it turns a hardening into a broken build if you miss
  it — `dtolnay/rust-toolchain` derives the channel it installs from
  `github.action_ref`, which is exactly how `@stable` means stable. Pinned to a
  SHA that default becomes the SHA, so every use now names `toolchain: stable`
  outright.

- **`bun install` runs with `--ignore-scripts`.** Nothing in the front end's
  tree needs a lifecycle script — esbuild and the tauri CLI ship their platform
  binaries as optional dependencies rather than postinstall downloads — so the
  scripts were only ever an unused path from a compromised package to a runner
  that holds the release secrets.

- **`release.yml` is `contents: read` at the workflow level**, and only the
  `release` job raises itself to `contents: write`. The three jobs that build
  and sign now carry a token that cannot publish a release.

- **Every `cargo` invocation takes `--locked`,** so CI fails on a lockfile that
  has drifted from the manifests instead of quietly resolving a different
  dependency tree than the one that was reviewed.

- **The keychain script fetches Apple's CA anchors over HTTPS only**
  (`--proto '=https' --proto-redir '=https' --tlsv1.2`). It passes `-L`, so
  without the redirect guard a 302 into `http://` would have been followed and
  the trust anchors taken in the clear.

### Added

- **A `core (Linux)` CI job**, retiring a TODO that turned out to be wrong about
  its own premise. `patchbay-core` has no `cfg(target_os)` branch anywhere: the
  macOS-shaped tool locations are plain strings built under a home directory the
  caller supplies, and the suite supplies a synthetic one; the Keychain path is
  covered through `MemoryKeystore`, so no test shells out to `security`. The
  core suite was already portable, and this job is what keeps it that way — it
  goes red the moment core reaches for a real `$HOME` or a platform cfg. It is
  not a claim that patchbay runs on Linux. `pb`, the panel and the probes are
  still macOS-only, which is why exactly one crate is built there.

### Fixed

- **The panel's clickable surfaces are real controls.** The tool card, the
  profile row's switch target, the copyable command and the detail scrim were
  each a non-interactive element wearing `role="button"`, a `tabIndex` and a
  hand-written Enter/Space handler; they are now `<button>`s, and the detail
  drawer is a native `<dialog>` — the same pair the key vault's drawer has used
  since it landed. The focus ring, the keyboard behaviour and the announced role
  come from the element instead of being re-implemented beside it. Nothing moves
  on screen: a button may only hold phrasing content, so the layout elements
  inside became spans and the stylesheet carries the boxes.

- The boot splash's light-mode text sat at 4.1:1 on its background, just under
  WCAG AA, while being the only thing on screen. It is now 5.3:1.

- `headlineExpiry` sorts with an explicit comparator. The default sort compares
  UTF-16 code units, which happens to be right for RFC 3339 stamps but said so
  nowhere.

## [0.3.0] - 2026-08-14

### Added

- **patchbay updates itself** — the panel checks the signed release feed a
  couple of seconds after launch and, when a newer build exists, says so in a
  slim banner above the board: `update and relaunch`, or `not now`. Applying is
  always a click — patchbay is a thing you open to answer a question about your
  logins, and an update must never be what happens instead — and the banner sits
  in the flow rather than over the board, so the answer you came for is never
  covered. The download is verified against a minisign public key compiled into
  the app before anything is installed, which is the whole reason this is
  allowed to be automatic at all. A failed check is silent: an offline machine
  has no update to offer, and that is not news. `not now` lasts for the session
  and is written nowhere, because something you have neither accepted nor
  refused should be asked again next launch. `pb check-updates` gained the
  matching row: patchbay reports its own installed version (the build answering
  the question, not whichever `pb` is on `PATH`) against the newest GitHub
  release, on the same 24-hour cache and the same shared rate limit as every
  other tool. Its `UPDATE WITH` is a human instruction — download the DMG, curl
  the CLI tarball — the way `gcloud`'s is, rather than a command that does not
  exist.

- **The panel writes to the key vault** — `add key` opens a form (id, provider,
  label, a masked secret field, with purpose, scopes, expiry, endpoint and the
  rotation checkbox folded away), and every row gets a trash affordance behind
  an inline confirm that says what removing does *not* do: the entry and its
  keychain value go, the credential keeps working until you revoke it at the
  provider. Both commands (`key_add`, `key_remove`) are thin wrappers over the
  same `KeyRegistry` calls the CLI makes, so the registry's rules — duplicate id
  refused unless you are rotating, empty secret refused, both-or-neither writes —
  and its error strings reach the panel verbatim. The vault view no longer tells
  you to go and use the command line. The secret exists in the field, the invoke
  payload and `KeyRegistry::add`, and nowhere else: it is cleared on submit,
  never logged, never echoed back. The panel still cannot *read* a value —
  `get_secret` is not wired up, there is no reveal and no copy, and `pb key copy`
  remains the only way one leaves the vault. The old CLI-only rule was about
  argv (`ps`, shell history), and a password field in a native window has
  neither.

- **The project env vault** ([`pb env`](docs/env-vault.md)) — the variables a
  *project* needs, held the way the key vault holds credentials: names and
  provenance in `~/.config/patchbay/projects.json` (`0600`), values in the macOS
  Keychain, and no plaintext `.env` anywhere. A project is a portable **name**,
  not a path: the manifest holds ids, environments and sync config and no
  absolute path at all, so copying it to another machine is the supported way to
  take your projects with you. Each of its environments has two layers: `synced`,
  which `pb env pull` replaces wholesale from Infisical, and `local`, which you
  set by hand and which wins on merge. Those are `.env.local` semantics, and
  they only hold because **patchbay never pushes** — there is no code path that
  writes a variable to a remote, so a local override is invisible to the cloud
  by construction rather than by policy, and a pull can never carry your
  container's `DATABASE_URL` into the team's shared set. Values are stored one
  Keychain item per project × environment × layer (account
  `env:<project>/<env>/<local|synced>`), holding the whole layer as one JSON
  blob, so an export is one Keychain round trip and not one per variable. No
  `last4` is recorded: four characters of `true` or `5432` is not a hint, it is
  the value. `pb env pull` also pins the account a project belongs to and checks
  it before spending a subprocess — the Infisical CLI's active login is
  machine-global, and under the wrong one the API answers 403 with "project does
  not belong to your selected organization", which reads like a problem with the
  project rather than with the login; patchbay refuses first and names
  `pb use infisical <email>` instead.
- **Two ways a directory resolves to a project**, in that order. An
  **attachment** (`pb env attach <id>` / `pb env detach`) binds a directory on
  this machine, in `~/.config/patchbay/attachments.json` — deepest attached
  ancestor wins, several roots per project, so every worktree and second clone
  shares one vault. A **marker** — a committed `.patchbay.toml` holding
  `project = "<id>"`, written by `pb env init` unless `--no-marker` — resolves
  a checkout by its content, so a fresh `git clone` works on any machine whose
  registry holds that project, with no attach step. An attachment always beats a
  marker: a deliberate local act outranks whatever the repo ships, and nothing
  in a repo can take that override back. A marker can only *name* a project the
  machine already has, and one that names an unknown project is a loud error
  pointing at the machine's `projects.json` rather than a silent miss. The
  tradeoff, taken deliberately: repo content selects which registered project's
  variables the tooling hands out, which assumes you run repos you trust.
- **Moving to a new machine** is therefore: bring `projects.json` over, clone the
  repo (the marker travels with it), `pb env pull`. `pb export` carries that
  manifest inside the bundle and `pb import` registers what is not here yet, so
  the migration path is the normal route and copying the file by hand is the
  fallback; a project id the destination already has is skipped with a note
  rather than overwritten, because the machine in front of you may be the newer
  one. What does **not** travel: `attachments.json`, since those are paths from
  a machine that is not this one; every variable value in either layer; and the
  local layer's variable *names* along with them, because a name with no value
  behind it would make `pb env list` promise what `pb env run` could not
  deliver. `SETUP.md`, the `pb plan` checklist and the `plan_setup` MCP tool
  each carry one `pb env pull --project <id>` per linked project, marked
  `auto: false` and naming the pinned account — a pull under the wrong
  machine-global infisical login fails confusingly, so `pb use infisical
  <email>` may have to come first. A project the old machine had *unlinked* but
  with a synced layer is a gap instead: nothing on the new machine can rebuild
  it.
- **`pb env`** — `init` (registers the project, attaches this directory, leaves
  a marker to commit, picking up `.infisical.json`), `attach`, `detach`,
  `link`, `projects`, `list`, `pull`, `set`, `unset`, `import`, `diff`, `run`,
  `export`, `forget`. `init` in a worktree of a project this machine already
  knows attaches it instead of failing on the duplicate id; `forget` takes the
  project, its Keychain blobs and this machine's attachments, and leaves
  committed markers alone (`rm .patchbay.toml`). `list` and `diff` answer from
  the name lists alone and never touch the Keychain; `set` takes its value from
  stdin or a hidden prompt, never argv; `run -- <cmd>` injects the merged
  environment into one child process and is the blessed read path, with
  `export` (dotenv or JSON, TTY warning) there for the cases where a file is
  genuinely what you need.
  `import <file>` bulk-loads an existing `.env` into the local layer,
  all-or-nothing, reporting a bad line by number and never by content.
- **MCP tools** — `list_env_projects`, `list_env_vars`, `pull_env` and
  `set_env_var`. `list_env_projects` reports each project's machine-local
  `roots` alongside its environments, and says what an empty list means, so an
  agent does not read a path there as where the user is working. The first two
  are metadata only; `pull_env` executes the Infisical CLI but its outcome
  carries counts and names, not values, so it is ungated;
  `set_env_var` is open like `store_key`, so an agent that creates a
  project credential registers it. Nothing reads a value back — not even behind
  `PATCHBAY_ALLOW_SECRET_READ`. An environment is dozens of secrets at once,
  and `pb env run` in your own terminal is the answer instead.

## [0.2.0] - 2026-08-13

### Added

- **ngrok** (`network`) — the agent's authentication, read from `ngrok.yml` at
  the v3 platform location, the legacy `~/.ngrok2` one, or `$NGROK_CONFIG`.
  One profile: the authenticated agent. Named `tunnels:` are forwarding rules on
  that one account, not identities, so they are reported as a count and a list
  in `meta`. `pb verify ngrok` runs `ngrok config check` and, when an `api_key`
  is configured, asks the ngrok API whether it is live — through the key vault's
  own HTTP seam, so the check is testable without the network. Neither the
  authtoken nor the api_key is ever reported, not even as a last4.

- **cloudflared** (`network`) — Cloudflare Tunnel origin certificates, and which
  one is in force. Profiles are the certificates, because that is the identity
  dimension: with two `*.pem` files on disk, every command uses `cert.pem`
  unless `TUNNEL_ORIGIN_CERT` or `--origincert` names the other, and nothing on
  the machine tells you which. That silent-wrong-account trap gets its own note.
  Tunnel credentials are read for their ids and account tags only —
  `TunnelSecret` has no field to deserialize into — and `cert.pem` is never
  parsed at all, since it carries a private key. `config.yml` (or
  `$TUNNEL_CONFIG`) contributes the tunnel name and ingress-rule count.

- A registered Cloudflare API token now puts a caveat on the `wrangler` row:
  it is a different credential from wrangler's OAuth login, with different
  reach, which `wrangler logout` does not revoke and `wrangler whoami` cannot
  see.

- **Grafana key verification** — `pb key verify` and the MCP `verify_key` now
  understand `--provider grafana`, asking `{endpoint}/api/org` and reporting the
  org the token belongs to. Grafana tokens are only meaningful against the
  instance that issued them, so `KeyEntry` gains an optional `endpoint`
  (`pb key add --endpoint https://<you>.grafana.net`, and the same field on the
  MCP `store_key`); a `keys.json` written before it existed keeps parsing, and
  keys without one never grow the field. A `grafana` key deliberately maps to no
  probe — there is no Grafana CLI for it to sit beside.

- **Machine migration** — `pb export` packs the logins that survive a machine
  move into one `age`-encrypted `.pbx` bundle: the portable credential files,
  optionally the key vault (`--keys`, off by default), a secret-free
  `manifest.json`, and a generated `SETUP.md` that tells a machine with no
  patchbay on it how to install one. `pb import` puts it back, backing up
  anything it would replace to `<path>.patchbay-bak`, and `--dry-run` prints the
  whole plan without writing a byte. Running an import twice produces the same
  machine.
- **A portability policy per tool** (`patchbay_core::migrate::policy`). Every
  probe declares `Portable`, `DeviceBound` or `PointerOnly` with the reason in
  the table — `gh`'s token is in the keychain, `tailscale`'s node key *is* this
  device, `ssh`'s private keys are never touched. A probe added without a policy
  fails the test suite. Files are collected and restored through `Paths` on both
  machines independently, so an override on either side is honoured.
- **`pb plan`, `pb status --diff <manifest>`, and the `plan_setup` /
  `mark_setup_done` MCP tools** — the gap list, re-derived from the machine in
  front of you rather than copied out of the manifest. Each item carries whether
  patchbay can close it itself, the exact command, and whether that command
  opens a browser. `mark_setup_done` re-probes rather than believing the agent
  that claims it ran something.
- Cloud-sync destinations (iCloud Drive, Dropbox, Google Drive, OneDrive, Box,
  pCloud) are refused without `--force`, with the reason: copying credential
  files is the technique sessions get hijacked with, and a bundle in a sync
  folder hands a service the whole set.
- No secret value leaves the encrypted payload — not into the manifest,
  `SETUP.md`, a log line, an error, `--json` or an MCP response. Decryption is
  in memory only: there is no staging directory, and each file goes straight to
  its destination through a temp file in that destination's own directory.

- **`pb use infisical <email>`** — the Infisical CLI's `user switch` is an
  arrow-key picker with no non-interactive form, so patchbay makes the same
  change itself: it repoints `loggedInUserEmail` and `LoggedInUserDomain` at one
  of the accounts already in `loggedInUsers`. Switching to an email that has
  never logged in is refused with the list of ones that have. No credential
  moves — every user's JWT stays in the vault backend, so the switch is followed
  by a note to run `infisical login status` if the JWT's freshness matters.

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

### Changed

- `patchbay_core::util` now owns the write-safety machinery MCP client
  management introduced — `backup`, `write_atomic` and a new
  `serialize_json_preserving_style` — so every probe that edits another tool's
  config gets the same rolling `.patchbay-bak`, the same atomic rename and the
  same house style on the way out. The style part is not cosmetic: the Infisical
  CLI writes one compact line with `": "` separators, and re-serializing it
  serde_json's way would rewrite every byte of the file for a one-field change.

### Fixed

- **kubectl** — a `~/.kube/config` that is a *directory* of per-cluster
  kubeconfigs (a common layout, and one kubectl itself chokes on) is now
  scanned instead of reported as zero contexts. The `*.yaml`/`*.yml` files
  directly inside it are merged first-file-wins, each context records the file
  it came from, files that are not kubeconfigs are skipped by name, and the
  note now spells out the `export KUBECONFIG=…` that makes a shell agree.
  Because every file carries its own `current-context`, no active context is
  reported unless exactly one file defines contexts.

- **15 new probes**, taking the board from 8 tools to 23: `vercel`, `firebase`,
  `neon`, `docker`, `tailscale`, `ssh`, `stripe`, `supabase`, `flyctl`,
  `doctl`, `npm`, `op`, `ollama`, `huggingface`, `claude`.
- **Four new categories** — `containers`, `network`, `payments`, `ai`. The
  panel's sidebar picks them up from the JSON.
- **Custom config paths.** Every probe honours the environment variable its own
  CLI honours, and patchbay gained an optional `~/.config/patchbay/config.toml`
  with a `[paths]` table for the case where there is no shell environment to
  inherit (the panel launched from Finder) or the state lives on another
  volume. Precedence is tool variable → `[paths]` → platform default, and an
  override in effect is named in the tool's `notes`. See "Custom paths" in the
  README.

### Fixed

- `gh` and `rclone` now honour `XDG_CONFIG_HOME`, as those CLIs do. `gcloud`
  deliberately still does not, because it does not either.

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

[Unreleased]: https://github.com/pathorsAI/patchbay/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/pathorsAI/patchbay/compare/v0.3.4...v0.4.0
[0.3.4]: https://github.com/pathorsAI/patchbay/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/pathorsAI/patchbay/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/pathorsAI/patchbay/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/pathorsAI/patchbay/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/pathorsAI/patchbay/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pathorsAI/patchbay/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pathorsAI/patchbay/releases/tag/v0.1.0
