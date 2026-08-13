#!/usr/bin/env bash
#
# Smoke test for the patchbay-mcp stdio server.
#
# Drives one full MCP session over stdin/stdout with no client library:
#
#   1. initialize                 -> serverInfo + instructions + capabilities
#   2. notifications/initialized  -> (no response; completes the handshake)
#   3. tools/list                 -> the five patchbay tools + their schemas
#   4. tools/call list_connections-> tier-1 board for this machine
#   5. tools/call get_status(nope)-> tool error listing the valid tool names
#
# Every line on stdout must be a JSON-RPC message: the test fails if the server
# prints anything else there (logs belong on stderr).
#
# Usage:
#   crates/patchbay-mcp/smoke.sh                  # builds if needed, uses debug binary
#   BIN=./target/release/patchbay-mcp crates/patchbay-mcp/smoke.sh
#
# Exit code 0 means every request got a well-formed, non-error response.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${BIN:-$ROOT/target/debug/patchbay-mcp}"
# Protocol version to negotiate. Override to test another one.
PROTOCOL="${PROTOCOL:-2024-11-05}"

if [[ ! -x "$BIN" ]]; then
  echo "smoke: building patchbay-mcp..." >&2
  cargo build --manifest-path "$ROOT/Cargo.toml" -p patchbay-mcp >&2
fi

out="$(mktemp)"
err="$(mktemp)"
trap 'rm -f "$out" "$err"' EXIT

# One JSON-RPC message per line. stdin closes after the last one, which is how
# the server is told to shut down.
{
  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"$PROTOCOL\",\"capabilities\":{},\"clientInfo\":{\"name\":\"smoke\",\"version\":\"0\"}}}"
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_connections","arguments":{}}}'
  printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_status","arguments":{"tool":"definitely-not-a-tool"}}}'
} | "$BIN" >"$out" 2>"$err"

echo "--- stdout (JSON-RPC) ---"
cat "$out"
echo "--- stderr (logs) ---"
cat "$err"
echo "-------------------------"

fail() { echo "smoke: FAIL: $*" >&2; exit 1; }

# stdout must be pure JSON-RPC, one message per line.
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  echo "$line" | python3 -c 'import json,sys; json.loads(sys.stdin.read())' \
    || fail "non-JSON line on stdout (logs must go to stderr): $line"
done <"$out"

# Four requests, four responses. Ids may come back out of order — the server
# handles calls concurrently — so the checks below key off the id, not order.
[[ "$(grep -c '"jsonrpc"' "$out")" -eq 4 ]] \
  || fail "expected 4 responses (ids 1-4), got $(grep -c '"jsonrpc"' "$out")"

python3 - "$out" <<'PY' || exit 1
import json, sys

msgs = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if line:
        m = json.loads(line)
        msgs[m.get("id")] = m

def need(cond, msg):
    if not cond:
        print(f"smoke: FAIL: {msg}", file=sys.stderr)
        sys.exit(1)

# 1. initialize
init = msgs.get(1)
need(init and "result" in init, "no initialize result")
r = init["result"]
need(r["serverInfo"]["name"] == "patchbay-mcp", "unexpected server name")
need("tools" in r["capabilities"], "server did not advertise tools capability")
need("tier 1" in r["instructions"], "instructions missing the tier-1/tier-2 guidance")

# 2. tools/list
tl = msgs.get(2)
need(tl and "result" in tl, "no tools/list result")
names = {t["name"] for t in tl["result"]["tools"]}
expected = {"list_connections", "get_status", "switch_profile", "verify", "get_permissions"}
need(names == expected, f"tool set mismatch: {sorted(names)}")
for t in tl["result"]["tools"]:
    need(t.get("description"), f"{t['name']} has no description")

# 3. tools/call list_connections -> JSON array of ToolStatus
lc = msgs.get(3)
need(lc and "result" in lc, "no list_connections result")
need(not lc["result"].get("isError"), "list_connections returned isError")
board = json.loads(lc["result"]["content"][0]["text"])
need(isinstance(board, list), "list_connections did not return a JSON array")
need(all({"tool", "installed", "profiles", "active", "notes"} <= set(s) for s in board),
     "ToolStatus shape mismatch")

# 4. unknown tool -> tool error whose message names the valid tools
bad = msgs.get(4)
need(bad and "result" in bad, "unknown tool should be a tool error, not a protocol error")
need(bad["result"].get("isError") is True, "unknown tool did not set isError")
text = bad["result"]["content"][0]["text"]
need("unknown tool" in text and "gcloud" in text,
     f"error message lost the valid-tool list: {text!r}")

print(f"smoke: OK - {len(board)} tools on the board: "
      + ", ".join(s["tool"] for s in board))
PY

echo "smoke: PASS"
