#!/usr/bin/env bash
#
# macos-keychain.sh — import the Developer ID signing identity into a throwaway
# keychain, and tear it down again.
#
#   macos-keychain.sh import    create the keychain and import the p12
#   macos-keychain.sh cleanup   delete it and restore the previous search list
#
# Both release jobs need the identity (the panel bundle *and* the bare `pb` /
# `patchbay-mcp` binaries), so the logic lives here instead of being pasted into
# two workflow steps.
#
# Environment:
#   SIGNING_CERTIFICATE           base64 of the Developer ID Application .p12
#   SIGNING_CERTIFICATE_PASSWORD  its export password
#   KEYCHAIN_PATH                 optional; defaults to $RUNNER_TEMP/build.keychain
#
# The secrets are deliberately NOT named APPLE_*: an empty APPLE_SIGNING_IDENTITY
# in the environment reads to tauri-bundler as "sign with the identity named
# empty string", which fails, whereas an unset one means "build unsigned". Only
# the caller promotes these to APPLE_* names, and only once it knows they are
# non-empty. See the release workflow.
#
# Nothing here touches the login keychain's contents. `default-keychain -s` does
# repoint the *default* for the duration; `cleanup` puts it back.

set -euo pipefail

keychain_path="${KEYCHAIN_PATH:-${RUNNER_TEMP:-/tmp}/build.keychain}"
state_dir="$(dirname "$keychain_path")"
orig_list_file="$state_dir/.keychain-original-list"
orig_default_file="$state_dir/.keychain-original-default"

die() {
    echo "::error::macos-keychain: $*" >&2
    exit 1
}

do_import() {
    : "${SIGNING_CERTIFICATE:?SIGNING_CERTIFICATE is empty}"
    : "${SIGNING_CERTIFICATE_PASSWORD:?SIGNING_CERTIFICATE_PASSWORD is empty}"

    local cert_path="$state_dir/certificate.p12"
    local keychain_password
    keychain_password="$(openssl rand -base64 24)"

    # Capture the current search list and default keychain BEFORE touching
    # anything. The existing keychains (login / System) carry the trusted Apple
    # Root anchor that the signing identity validates against, and cleanup needs
    # them to put the machine back the way it found it.
    #
    # Strip the indent and the surrounding quotes only — NOT interior spaces.
    # `security list-keychains` prints one entry per line, and an entry can
    # contain a space (usually because something previously re-set the list from
    # an unquoted variable and collapsed two paths into one). Deleting spaces
    # would silently rewrite such an entry, so each line is kept whole and
    # restored as a single argument.
    local original_keychains=()
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}" # leading whitespace
        line="${line%\"}"
        line="${line#\"}"
        [[ -n "$line" ]] && original_keychains+=("$line")
    done < <(security list-keychains -d user)
    printf '%s\n' "${original_keychains[@]}" >"$orig_list_file"
    security default-keychain -d user | tr -d '" ' >"$orig_default_file" || true

    security create-keychain -p "$keychain_password" "$keychain_path"
    security default-keychain -s "$keychain_path"
    security unlock-keychain -p "$keychain_password" "$keychain_path"

    # Push the idle auto-lock out to 6h. A fresh keychain otherwise re-locks
    # after ~5min idle, and the release build runs far longer than that before
    # codesign is reached — a re-locked keychain makes codesign hang on an auth
    # prompt that can never be answered on a runner.
    #
    # Note -lut is -l -u -t: it DOES leave lock-on-sleep enabled (verified with
    # show-keychain-info; some copies of this snippet claim otherwise). That is
    # fine here only because CI runners do not sleep. If you reuse this on a
    # laptop, drop the `l` or the keychain locks on lid-close mid-build.
    security set-keychain-settings -lut 21600 "$keychain_path"

    printf '%s' "$SIGNING_CERTIFICATE" | base64 --decode >"$cert_path"
    # -T grants codesign/productsign access to the imported private key.
    security import "$cert_path" -P "$SIGNING_CERTIFICATE_PASSWORD" \
        -t cert -f pkcs12 -k "$keychain_path" \
        -T /usr/bin/codesign -T /usr/bin/productsign
    rm -f "$cert_path"

    # The exported .p12 holds only the leaf cert, not Apple's intermediate/root.
    # Runners normally already have them; import best-effort and tolerate the
    # non-zero "already exists" so this does not abort under `set -e`.
    curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
        -o "$state_dir/DeveloperIDG2CA.cer" \
        https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer || true
    curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
        -o "$state_dir/AppleRoot.cer" \
        https://www.apple.com/appleca/AppleIncRootCertificate.cer || true
    security import "$state_dir/DeveloperIDG2CA.cer" -k "$keychain_path" 2>/dev/null || true
    security import "$state_dir/AppleRoot.cer" -k "$keychain_path" 2>/dev/null || true

    # Without codesign: in the partition list, codesign blocks on a GUI keychain
    # prompt instead of using the key.
    security set-key-partition-list -S apple-tool:,apple:,codesign: \
        -s -k "$keychain_password" "$keychain_path" >/dev/null

    # `default-keychain -s` does NOT put the keychain on the search list, and
    # codesign resolves identities via the SEARCH LIST. Prepend ours, keep the
    # originals so the Apple Root trust anchor still resolves. Each original is
    # passed as its own argument (quoted) — expanding an unquoted variable here
    # is what merges two paths into one bogus entry.
    security list-keychains -d user -s "$keychain_path" "${original_keychains[@]}"

    # `find-identity` exits 0 even when it found nothing, so assert on the text.
    # Failing here is much easier to read than an ambiguous codesign error an
    # hour into the build.
    local identities
    identities="$(security find-identity -v -p codesigning "$keychain_path")"
    printf '%s\n' "$identities"
    printf '%s' "$identities" | grep -qE '[1-9][0-9]* valid identities found' ||
        die "no valid code-signing identity in the keychain (incomplete cert chain?)"
}

do_cleanup() {
    # Best-effort throughout: this runs with `if: always()`, including after a
    # failure that happened before the keychain ever existed.
    if [[ -f "$orig_default_file" ]]; then
        local original_default
        original_default="$(cat "$orig_default_file")"
        [[ -n "$original_default" ]] && security default-keychain -s "$original_default" || true
    fi

    if [[ -f "$orig_list_file" ]]; then
        local restore=()
        while IFS= read -r line; do
            [[ -n "$line" ]] && restore+=("$line")
        done <"$orig_list_file"
        [[ ${#restore[@]} -gt 0 ]] && security list-keychains -d user -s "${restore[@]}" || true
    fi

    # delete-keychain also drops it from the search list.
    [[ -f "$keychain_path" ]] && security delete-keychain "$keychain_path" || true
    rm -f "$orig_list_file" "$orig_default_file" "$state_dir/certificate.p12"
    echo "macos-keychain: cleaned up $keychain_path"
}

case "${1:-}" in
import) do_import ;;
cleanup) do_cleanup ;;
*) die "usage: macos-keychain.sh {import|cleanup}" ;;
esac
