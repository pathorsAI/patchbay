import type { Meta, PermissionsReport, SwitchOutcome, VerifyOutcome } from "./types";

/**
 * What the main pane is showing. The board is the app; the other two are
 * read-only surfaces onto the same machine that the board cannot express —
 * keys no CLI tracks, and MCP servers that belong to clients rather than tools.
 */
export type View = "board" | "keys" | "mcp";

/** A finished switch attempt, flattened for display. */
export interface SwitchNote {
  text: string;
  hint?: string;
  bad: boolean;
}

/**
 * The panel's shared state and operations. The board and the detail view are
 * two views onto the same thing: a verify run from a card is still there when
 * the tool's detail opens, and a switch from either re-reads the board.
 */
/** The key a per-profile result is filed under. */
export function rowKey(tool: string, profileId: string): string {
  return `${tool}:${profileId}`;
}

export interface Panel {
  now: number;
  /**
   * Keyed by `rowKey`: verification is per profile, because "is this login
   * still good?" is a question about a credential, not about a tool.
   * `null` = in flight, `undefined` = never run. Results persist until the
   * next board refresh, so an answer does not vanish while you read it.
   */
  verdicts: Record<string, VerifyOutcome | null>;
  perms: Record<string, PermissionsReport | null>;
  /** `rowKey` of the switch in flight. */
  switching: string | null;
  switchNotes: Record<string, SwitchNote>;
  verifyRow(tool: string, profileId: string): void;
  loadPerms(tool: string): void;
  switchTo(tool: string, profileId: string): void;
  open(tool: string, opts?: { permissions?: boolean }): void;
}

export function switchMessage(outcome: SwitchOutcome): SwitchNote {
  switch (outcome.result) {
    case "switched":
      return { text: [outcome.detail, ...outcome.notes].join(" — "), bad: false };
    case "unsupported":
      return { text: outcome.reason, hint: outcome.hint ?? undefined, bad: false };
    case "unknown_profile":
      return { text: `no such profile: ${outcome.profile_id}`, bad: true };
    case "failed":
      return { text: outcome.detail, bad: true };
  }
}

export function verdictText(v: VerifyOutcome): string {
  return v.result === "unsupported" ? v.reason : v.detail;
}

/** Meta keys worth surfacing on the face of a card, most identifying first. */
const META_ORDER = [
  "account",
  "user",
  "project",
  "subscription",
  "host",
  "cluster",
  "namespace",
  "domain",
  "tenant_domain",
  "remote",
  "type",
  "source",
];

/** Scalar meta entries, ordered so the identifying ones come first. */
export function metaEntries(meta: Meta): [string, string][] {
  const entries = Object.entries(meta).filter(
    ([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean",
  );
  entries.sort((a, b) => {
    const ia = META_ORDER.indexOf(a[0]);
    const ib = META_ORDER.indexOf(b[0]);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a[0].localeCompare(b[0]);
  });
  return entries.map(([k, v]) => [k, String(v)]);
}

/** The one-line summary a card shows under the active profile. */
export function metaLine(meta: Meta): string {
  return metaEntries(meta)
    .filter(([, v]) => v !== "true" && v !== "false")
    .slice(0, 3)
    .map(([, v]) => v)
    .join(" · ");
}
