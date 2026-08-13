/**
 * Every tool the core reports must have a brand mark in the panel.
 *
 * The failure this prevents is quiet and had already happened twice: someone
 * lands a probe, the board grows a card, and that card shows a two-letter
 * monogram next to twenty real logos. Nobody notices in review because the
 * board looks fine in the screenshot the author took before adding the probe.
 *
 * So it is a build failure instead. This is a set difference and nothing more:
 * the tool keys `pb status --json` emits, minus the keys `ToolLogo.tsx`
 * registers. Non-empty means a missing mark.
 *
 * Usage (from the repo root):
 *   cargo run -q -p patchbay-cli -- status --json | bun scripts/ci/logo-check.ts
 */

import { MARK_KEYS } from "../../app/src/components/ToolLogo";

const raw = await Bun.stdin.text();

let reported: string[];
try {
  reported = (JSON.parse(raw) as { tool: string }[]).map((s) => s.tool);
} catch (e) {
  console.error("logo check: could not parse `pb status --json` from stdin");
  console.error(String(e));
  process.exit(2);
}

if (reported.length === 0) {
  // An empty board means the CLI failed or emitted nothing; passing here would
  // make the check vacuously green exactly when it is least able to see.
  console.error("logo check: `pb status --json` reported no tools at all");
  process.exit(2);
}

const marks = new Set(MARK_KEYS);
const missing = reported.filter((t) => !marks.has(t));

// The other direction is a warning, not a failure: a mark can legitimately
// outlive a probe that was renamed or is not detected on this machine.
const orphans = MARK_KEYS.filter((k) => !reported.includes(k));

if (missing.length > 0) {
  for (const tool of missing) {
    console.error(
      `tool '${tool}' has no logo — add a mark to app/src/components/ToolLogo.tsx`,
    );
  }
  console.error(
    `\n${missing.length} of ${reported.length} tools are missing a brand mark.` +
      "\nSee CONTRIBUTING.md — a new probe is not done until its mark ships.",
  );
  process.exit(1);
}

console.log(`logo check: ${reported.length} tools, ${reported.length} marks, none missing`);
if (orphans.length > 0) {
  console.log(`  (marks with no probe on this machine: ${orphans.join(", ")})`);
}
