import type { ToolStatus } from "./types";

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
 * for tools with no active profile (rclone) — the soonest one it knows about.
 */
export function headlineExpiry(status: ToolStatus): string | null {
  const active = status.profiles.find((p) => p.id === status.active);
  if (active) return active.expires_at;
  const known = status.profiles
    .map((p) => p.expires_at)
    .filter((e): e is string => Boolean(e))
    // Explicit comparator: the default sort compares UTF-16 code units, which
    // happens to be right for RFC 3339 stamps but says so nowhere.
    .sort((a, b) => a.localeCompare(b));
  return known[0] ?? null;
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
    switch (levelOf(headlineExpiry(status), now)) {
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
