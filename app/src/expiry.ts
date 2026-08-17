import type { Expiry, Profile, ToolStatus } from "./types";

export type Level = "ok" | "warn" | "critical" | "expired" | "unknown";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** Severity of an expiry timestamp relative to `now`. */
export function levelOf(expiresAt: string | null, now: number): Level {
  if (!expiresAt) return "unknown";
  const left = Date.parse(expiresAt) - now;
  if (Number.isNaN(left)) return "unknown";
  if (left <= 0) return "expired";
  if (left < DAY) return "critical";
  if (left < 7 * DAY) return "warn";
  return "ok";
}

/** "in 32m" / "expired 152d" — always two tokens, never a wall-clock date. */
export function countdown(expiresAt: string | null, now: number): string {
  if (!expiresAt) return "no expiry";
  const at = Date.parse(expiresAt);
  if (Number.isNaN(at)) return "expiry unreadable";
  const delta = at - now;
  const span = magnitude(Math.abs(delta));
  return delta <= 0 ? `expired ${span}` : `in ${span}`;
}

function magnitude(ms: number): string {
  if (ms < MINUTE) return `${Math.max(1, Math.round(ms / 1000))}s`;
  if (ms < HOUR) return `${Math.round(ms / MINUTE)}m`;
  if (ms < DAY) return `${Math.round(ms / HOUR)}h`;
  return `${Math.round(ms / DAY)}d`;
}

/**
 * The expiry that decides a tool's headline state: the active profile's, or —
 * for tools with no active profile (rclone) — the soonest real deadline it
 * knows about, falling back to the first profile's state so a tool that simply
 * never expires says so instead of saying nothing.
 */
export function headlineExpiry(status: ToolStatus): Expiry {
  const active = status.profiles.find((p) => p.id === status.active);
  if (active) return active.expiry;
  const dated = status.profiles
    .filter((p): p is Profile & { expiry: { state: "at"; at: string } } => p.expiry.state === "at")
    // Explicit comparator: the default sort compares UTF-16 code units, which
    // happens to be right for RFC 3339 stamps but says so nowhere.
    .sort((a, b) => a.expiry.at.localeCompare(b.expiry.at));
  return dated[0]?.expiry ?? status.profiles[0]?.expiry ?? { state: "unknown" };
}

/**
 * Severity of an `Expiry`. Only a real deadline can be urgent: a credential
 * that never expires is not a warning, and a token the CLI renews behind your
 * back is not a countdown. Both used to render as the same colourless "no
 * expiry" as a genuinely unreadable one, which is how a board of healthy tools
 * came to look like a board of unknowns.
 */
export function expiryLevel(e: Expiry, now: number): Level {
  return e.state === "at" ? levelOf(e.at, now) : "unknown";
}

/** The chip's text: two tokens, never a wall-clock date. */
export function expiryText(e: Expiry, now: number): string {
  switch (e.state) {
    case "at":
      return countdown(e.at, now);
    case "no_expiry":
      return "no expiry";
    case "refreshable":
      return "auto-renewed";
    default:
      return "expiry unknown";
  }
}

/** The chip's tooltip: the sentence the note used to be. */
export function expiryTitle(e: Expiry): string {
  switch (e.state) {
    case "at":
      return e.at;
    case "no_expiry":
      return "this credential does not expire by design";
    case "refreshable":
      return e.access_token_expires
        ? `the CLI renews this silently; its current access token runs out ${e.access_token_expires}`
        : "the CLI renews this silently, so there is no deadline to meet";
    default:
      return e.reason
        ? `patchbay cannot read this expiry: it lives ${e.reason}`
        : "patchbay cannot read this expiry";
  }
}

export interface Summary {
  tools: number;
  soon: number;
  expired: number;
}

export function summarize(all: ToolStatus[], now: number): Summary {
  let soon = 0;
  let expired = 0;
  for (const status of all) {
    switch (expiryLevel(headlineExpiry(status), now)) {
      case "expired":
        expired += 1;
        break;
      case "critical":
      case "warn":
        soon += 1;
        break;
      default:
        break;
    }
  }
  return { tools: all.length, soon, expired };
}

export function summaryLine(s: Summary): string {
  const parts = [`${s.tools} ${s.tools === 1 ? "tool" : "tools"}`];
  if (s.soon) parts.push(`${s.soon} expiring soon`);
  if (s.expired) parts.push(`${s.expired} expired`);
  if (!s.soon && !s.expired && s.tools) parts.push("nothing expiring");
  return parts.join(" · ");
}

export function clockTime(at: number): string {
  return new Date(at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}
