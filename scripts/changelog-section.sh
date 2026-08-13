#!/usr/bin/env bash
#
# changelog-section.sh <version> — print the CHANGELOG body for one release.
#
# Reads CHANGELOG.md and emits everything between `## [<version>]` and the next
# `## ` heading, with the heading itself dropped. Prints nothing and exits 0 if
# the version has no section, so the release workflow can fall back to
# auto-generated notes instead of failing.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:?usage: changelog-section.sh <version>}"
changelog="${2:-$repo_root/CHANGELOG.md}"

[ -f "$changelog" ] || exit 0

awk -v want="$version" '
    /^## / {
        # A new section always ends the one we were printing.
        if (printing) exit
        # Match "## [1.2.3] - date" and "## 1.2.3 - date" alike.
        heading = $0
        sub(/^## +/, "", heading)
        sub(/^\[/, "", heading)
        sub(/\].*$/, "", heading)
        sub(/ .*$/, "", heading)
        if (heading == want) { printing = 1; next }
        next
    }
    # The link-reference block at the foot of the file belongs to no section.
    printing && /^\[[^]]+\]: / { exit }
    printing { print }
' "$changelog" | sed -e '/./,$!d' | awk '{ lines[NR] = $0 } END { last = NR; while (last > 0 && lines[last] ~ /^[[:space:]]*$/) last--; for (i = 1; i <= last; i++) print lines[i] }'
