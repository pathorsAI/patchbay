import type { ConnectionState, Profile, ToolCategory, ToolStatus } from "./types";

export interface Filters {
  /** `null` = every category. */
  category: ToolCategory | null;
  /** `null` = every connection state. */
  state: ConnectionState | null;
  query: string;
}

export const NO_FILTERS: Filters = { category: null, state: null, query: "" };

export function isFiltered(f: Filters): boolean {
  return f.category !== null || f.state !== null || f.query.trim() !== "";
}

/**
 * Substring matching, every whitespace-separated term must hit somewhere:
 * the tool key, or one of its profile ids/labels. Deliberately not a fuzzy
 * ranker — on a board of eight tools, predictable beats clever.
 */
function terms(query: string): string[] {
  return query.toLowerCase().split(/\s+/).filter(Boolean);
}

export function profileMatches(profile: Profile, query: string): boolean {
  const ts = terms(query);
  if (!ts.length) return false;
  const hay = `${profile.id} ${profile.label}`.toLowerCase();
  return ts.every((t) => hay.includes(t));
}

export function matchesQuery(status: ToolStatus, query: string): boolean {
  const ts = terms(query);
  if (!ts.length) return true;
  const tool = status.tool.toLowerCase();
  const profiles = status.profiles.map((p) => `${p.id} ${p.label}`.toLowerCase());
  // A term may match the tool name or any one profile; all terms must land.
  return ts.every((t) => tool.includes(t) || profiles.some((p) => p.includes(t)));
}

export function apply(statuses: ToolStatus[], f: Filters): ToolStatus[] {
  return statuses.filter(
    (s) =>
      matchesQuery(s, f.query) &&
      (f.category === null || s.category === f.category) &&
      (f.state === null || s.connection_state === f.state),
  );
}

/**
 * Counts for the sidebar. They follow the search box but ignore the current
 * category/state selection, so the numbers do not shift under the cursor as
 * you click between them.
 */
export function counts(statuses: ToolStatus[], query: string) {
  const searched = statuses.filter((s) => matchesQuery(s, query));
  const byCategory = new Map<ToolCategory, number>();
  const byState = new Map<ConnectionState, number>();
  for (const s of searched) {
    byCategory.set(s.category, (byCategory.get(s.category) ?? 0) + 1);
    byState.set(s.connection_state, (byState.get(s.connection_state) ?? 0) + 1);
  }
  return { total: searched.length, byCategory, byState };
}
