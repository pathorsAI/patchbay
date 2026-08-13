#!/usr/bin/env bash
#
# bump-version.sh — one version, four files.
#
# patchbay's version lives in four places that must agree, because three
# different build systems read three different ones:
#
#   Cargo.toml                    [workspace.package] version  -> pb, patchbay-mcp
#   app/src-tauri/Cargo.toml      [package] version            -> the panel crate
#   app/src-tauri/tauri.conf.json version                      -> the .app / .dmg
#   app/package.json              version                      -> the front end
#
# Usage:
#   scripts/bump-version.sh 0.2.0        set all four (and refresh both lockfiles)
#   scripts/bump-version.sh --check      assert all four already agree
#   scripts/bump-version.sh --check 0.2.0
#                                        ...and that they equal 0.2.0
#
# --check is what the release workflow runs against the pushed tag.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

root_cargo="Cargo.toml"
app_cargo="app/src-tauri/Cargo.toml"
tauri_conf="app/src-tauri/tauri.conf.json"
app_pkg="app/package.json"

die() {
    echo "bump-version: $*" >&2
    exit 1
}

# Each reader is anchored so it can only ever match the one top-level version
# key: dependency versions are inline (`{ version = "2" }`) or nested deeper
# than two spaces, and never start a line at column 0 / indent 2.
read_root_cargo() { sed -n 's/^version = "\(.*\)"$/\1/p' "$root_cargo" | head -1; }
read_app_cargo() { sed -n 's/^version = "\(.*\)"$/\1/p' "$app_cargo" | head -1; }
read_tauri_conf() { sed -n 's/^  "version": "\(.*\)",\{0,1\}$/\1/p' "$tauri_conf" | head -1; }
read_app_pkg() { sed -n 's/^  "version": "\(.*\)",\{0,1\}$/\1/p' "$app_pkg" | head -1; }

collect() {
    root_version="$(read_root_cargo)"
    app_cargo_version="$(read_app_cargo)"
    tauri_version="$(read_tauri_conf)"
    pkg_version="$(read_app_pkg)"

    [ -n "$root_version" ] || die "no version found in $root_cargo"
    [ -n "$app_cargo_version" ] || die "no version found in $app_cargo"
    [ -n "$tauri_version" ] || die "no version found in $tauri_conf"
    [ -n "$pkg_version" ] || die "no version found in $app_pkg"
}

report() {
    printf '  %-30s %s\n' \
        "$root_cargo" "$root_version" \
        "$app_cargo" "$app_cargo_version" \
        "$tauri_conf" "$tauri_version" \
        "$app_pkg" "$pkg_version"
}

check() {
    local expected="${1:-}"
    collect

    if [ "$root_version" != "$app_cargo_version" ] ||
        [ "$root_version" != "$tauri_version" ] ||
        [ "$root_version" != "$pkg_version" ]; then
        echo "bump-version: versions disagree:" >&2
        report >&2
        echo "run: scripts/bump-version.sh <semver>" >&2
        exit 1
    fi

    if [ -n "$expected" ] && [ "$expected" != "$root_version" ]; then
        die "expected version $expected, but the tree says $root_version"
    fi

    echo "version $root_version (all four files agree)"
}

# In-place edit that works with both BSD sed (macOS) and GNU sed (Linux).
sed_i() {
    local expr="$1" file="$2"
    local tmp
    tmp="$(mktemp)"
    sed "$expr" "$file" >"$tmp"
    mv "$tmp" "$file"
}

bump() {
    local new="$1"

    printf '%s' "$new" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' ||
        die "'$new' is not a semver like 1.2.3 (no leading v)"

    collect
    echo "bumping $root_version -> $new"

    sed_i "s/^version = \".*\"$/version = \"$new\"/" "$root_cargo"
    sed_i "s/^version = \".*\"$/version = \"$new\"/" "$app_cargo"
    sed_i "s/^  \"version\": \".*\"\(,\{0,1\}\)$/  \"version\": \"$new\"\1/" "$tauri_conf"
    sed_i "s/^  \"version\": \".*\"\(,\{0,1\}\)$/  \"version\": \"$new\"\1/" "$app_pkg"

    # Both lockfiles pin the workspace crates by version, so they go stale the
    # moment the manifests move. --workspace touches only our own crates.
    if command -v cargo >/dev/null 2>&1; then
        cargo update --workspace --quiet
        (cd app/src-tauri && cargo update --workspace --quiet)
    else
        echo "bump-version: cargo not found; Cargo.lock files not refreshed" >&2
    fi

    check "$new"
}

case "${1:-}" in
"" | -h | --help)
    sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    [ -n "${1:-}" ] || exit 1
    ;;
--check)
    check "${2:-}"
    ;;
*)
    bump "$1"
    ;;
esac
