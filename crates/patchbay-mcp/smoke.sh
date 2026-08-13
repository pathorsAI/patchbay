#!/usr/bin/env bash
#
# Smoke test for the patchbay-mcp stdio server.
#
# Drives one full MCP session over stdin/stdout with no client library:
#
#   1. initialize                 -> serverInfo + instructions + capabilities
#   2. notifications/initialized  -> (no response; completes the handshake)
#   3. tools/list                 -> every patchbay tool + its schema
#   4. tools/call list_connections-> tier-1 board for this machine
#   5. tools/call get_status(nope)-> tool error listing the valid tool names
#   6. tools/call list_keys       -> the key vault, metadata only
#   7. tools/call get_key         -> REFUSED, because PATCHBAY_ALLOW_SECRET_READ
#                                    is not set on the server process
#   8. tools/call list_mcp_clients-> the MCP client board, env NAMES only
#
# Nothing here writes: no key is stored, and the vault is only read. Step 7 is
# the important one - it is the assertion that the read gate is closed by
# default, which is the whole security story of the vault.
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
  printf '%s\n' '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_keys","arguments":{}}}'
  printf '%s\n' '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_key","arguments":{"id":"anything"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"list_mcp_clients","arguments":{}}}'
# The gate must be closed because the variable is unset, so make sure it is -
# a value inherited from the developer's shell would silently void step 7.
} | env -u PATCHBAY_ALLOW_SECRET_READ "$BIN" >"$out" 2>"$err"

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

# Seven requests, seven responses. Ids may come back out of order — the server
# handles calls concurrently — so the checks below key off the id, not order.
[[ "$(grep -c '"jsonrpc"' "$out")" -eq 7 ]] \
  || fail "expected 7 responses (ids 1-7), got $(grep -c '"jsonrpc"' "$out")"

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
need("PATCHBAY_ALLOW_SECRET_READ" in r["instructions"],
     "instructions never mention the key vault's read gate")
# The env/credential routing rule: every client must see it on connect.
need("WHERE DOES THIS CREDENTIAL GO?" in r["instructions"],
     "instructions lost the credential routing rule")
need("secret manager" in r["instructions"] and "Infisical" in r["instructions"],
     "routing rule does not send app env to the project's secret manager")

# 2. tools/list
tl = msgs.get(2)
need(tl and "result" in tl, "no tools/list result")
names = {t["name"] for t in tl["result"]["tools"]}
expected = {"list_connections", "get_status", "switch_profile", "verify", "get_permissions",
            "store_key", "list_keys", "get_key", "remove_key", "verify_key",
            "list_mcp_clients", "add_mcp_server", "copy_mcp_server", "remove_mcp_server"}
need(names == expected, f"tool set mismatch: {sorted(names)}")
for t in tl["result"]["tools"]:
    need(t.get("description"), f"{t['name']} has no description")

# 3. tools/call list_connections -> JSON array of ToolStatus
lc = msgs.get(3)
need(lc and "result" in lc, "no list_connections result")
need(not lc["result"].get("isError"), "list_connections returned isError")
board = json.loads(lc["result"]["content"][0]["text"])
need(isinstance(board, list), "list_connections did not return a JSON array")
need(all({"tool", "installed", "profiles", "active", "notes", "registered_keys"} <= set(s)
         for s in board),
     "ToolStatus shape mismatch")

# 4. unknown tool -> tool error whose message names the valid tools
bad = msgs.get(4)
need(bad and "result" in bad, "unknown tool should be a tool error, not a protocol error")
need(bad["result"].get("isError") is True, "unknown tool did not set isError")
text = bad["result"]["content"][0]["text"]
need("unknown tool" in text and "gcloud" in text,
     f"error message lost the valid-tool list: {text!r}")

# 5. list_keys -> metadata only, never a value
lk = msgs.get(5)
need(lk and "result" in lk, "no list_keys result")
need(not lk["result"].get("isError"), f"list_keys returned isError: {lk['result']}")
vault = json.loads(lk["result"]["content"][0]["text"])
need(isinstance(vault, list), "list_keys did not return a JSON array")
for entry in vault:
    need({"id", "provider", "label", "last4", "expiry_state", "linked_tool"} <= set(entry),
         f"key entry shape mismatch: {sorted(entry)}")
    need("secret" not in entry, f"list_keys leaked a secret field for {entry['id']!r}")

# 6. get_key without the env flag -> refused, with the flag and the human path
#    named in the message. This is the gate; if it ever passes silently, the
#    vault's whole read policy is gone.
gk = msgs.get(6)
need(gk and "result" in gk, "no get_key result")
need(gk["result"].get("isError") is True,
     "get_key was NOT refused without PATCHBAY_ALLOW_SECRET_READ")
text = gk["result"]["content"][0]["text"]
need("PATCHBAY_ALLOW_SECRET_READ" in text, f"refusal does not name the flag: {text!r}")
need("pb key copy" in text, f"refusal does not offer the human path: {text!r}")

# 7. list_mcp_clients -> the client board, metadata only. Read-only: nothing in
#    this script writes to a real client config.
mc = msgs.get(7)
need(mc and "result" in mc, "no list_mcp_clients result")
need(not mc["result"].get("isError"), f"list_mcp_clients returned isError: {mc['result']}")
clients = json.loads(mc["result"]["content"][0]["text"])
need(isinstance(clients, list), "list_mcp_clients did not return a JSON array")
for c in clients:
    need({"client", "label", "config_path", "present", "servers", "notes"} <= set(c),
         f"client shape mismatch: {sorted(c)}")
    for srv in c["servers"]:
        need({"name", "transport", "env_keys"} <= set(srv),
             f"server shape mismatch: {sorted(srv)}")
        # The hard rule: names, never values. `env`/`headers` blocks and raw
        # argument lists must never reach a caller.
        need(not ({"env", "headers", "args"} & set(srv)),
             f"list_mcp_clients leaked values for {srv['name']!r}: {sorted(srv)}")

print(f"smoke: OK - {len(board)} tools on the board: "
      + ", ".join(s["tool"] for s in board))
print(f"smoke: OK - key vault reachable ({len(vault)} registered), "
      "get_key refused without PATCHBAY_ALLOW_SECRET_READ")
configured = [c["client"] for c in clients if c["present"]]
print(f"smoke: OK - MCP clients: {len(clients)} known, configured: "
      + (", ".join(configured) or "none"))
PY

echo "smoke: PASS"
