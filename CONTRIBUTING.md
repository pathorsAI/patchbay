# Contributing

Thanks for looking. patchbay is small and early — issues, probe fixes and new
probes are all welcome.

## Toolchain

- **Rust stable** (via [rustup](https://rustup.rs)) with `rustfmt` and `clippy`
- **[bun](https://bun.sh)** — the panel's front end; there is no npm fallback
- **macOS** for now. The probes read macOS-shaped paths; Linux support is
  mostly path mapping and is not wired up yet.

## Running things

```sh
cargo test --workspace                     # every probe's unit tests
cargo run -p patchbay-cli -- status        # the board in your terminal
cargo run -p patchbay-cli -- status --json # what the panel and MCP server see
cargo run -p patchbay-mcp                  # the MCP server on stdio
```

The panel (`app/src-tauri` is deliberately outside the root Cargo workspace, so
it builds standalone):

```sh
cd app
bun install
bunx tauri dev      # panel + hot-reloading front end
bunx tauri build    # bundle a .app / .dmg
```

## Before you open a PR

CI runs exactly these; run them first and save yourself a round trip:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

cd app && bun install --frozen-lockfile && bun run build
cd app/src-tauri && cargo clippy --all-targets -- -D warnings
```

## Commit messages

Bracketed type prefix, imperative, lower case:

```
[feature] add a probe for doctl
[fix] gcloud probe no longer reports ADC as a profile
[chore] bump rmcp to 3.2
[refactor] fold the expiry parsers into util
[docs] document the tier-1 / tier-2 split
```

Types: `[feature]`, `[fix]`, `[chore]`, `[refactor]`, `[docs]`.

## PR flow

1. Branch off `main`.
2. Keep the PR to one idea. A new probe is one PR; a probe plus a CLI redesign
   is two.
3. Add tests. A probe without tests will not be merged.
4. Add a bullet to the `## [Unreleased]` section of `CHANGELOG.md` for anything
   a user would notice.
5. Green CI, then request review.

## Review rules that are not negotiable

**Probes must never log, serialize or return a token value.** patchbay reports
*metadata about* credentials: which account, which profile, when it expires,
what scopes it carries. The credential itself is parsed only far enough to
extract that metadata and is then dropped. Concretely, a change is rejected if
a secret value can reach:

- a `ToolStatus`, `Profile`, `PermissionsReport` or any other serialized type
- an `anyhow` context string, a panic message or any `eprintln!` / `tracing`
  call — including on the error path, which is where this usually slips in
- a `Debug` impl. If a struct holds a secret, it does not get `#[derive(Debug)]`.

If you need to prove a token works, shell out to the tool's own CLI (`pb
verify`) rather than moving the token around yourself.

**Tests use fixture directories, never the real `$HOME`.** Every probe test
builds a `tempfile::TempDir`, writes the state files it wants to exercise, and
points `Paths` at it. A test that reads the developer's actual `~/.config`
passes on the author's machine, fails in CI, and — worse — its result depends on
who is logged into what. If you find yourself wanting the real home directory,
you want another fixture.

## Releases

Maintainers only. Version lives in four files kept in sync by
`scripts/bump-version.sh`; see the release section of that script's header. CI
refuses a tag whose version does not match the tree.
