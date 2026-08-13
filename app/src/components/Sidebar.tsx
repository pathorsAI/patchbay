import { forwardRef } from "react";
import type { Filters } from "../filters";
import { counts } from "../filters";
import {
  CATEGORY_LABEL,
  STATE_LABEL,
  STATES,
  type ConnectionState,
  type ToolCategory,
  type ToolStatus,
} from "../types";

/** Categories in a fixed order, so the list does not reshuffle as tools change. */
const CATEGORY_ORDER: ToolCategory[] = [
  "cloud",
  "code",
  "secrets",
  "cluster",
  "edge",
  "storage",
  "other",
];

interface Props {
  statuses: ToolStatus[];
  filters: Filters;
  onChange(next: Filters): void;
}

/**
 * The board's index: search at the top, what a tool is in the middle, how it
 * is doing at the bottom. Category and state compose with AND; "All" in either
 * list clears that dimension only.
 */
export const Sidebar = forwardRef<HTMLInputElement, Props>(function Sidebar(
  { statuses, filters, onChange },
  searchRef,
) {
  const { total, byCategory, byState } = counts(statuses, filters.query);
  const categories = CATEGORY_ORDER.filter((c) => (byCategory.get(c) ?? 0) > 0);

  return (
    <nav className="sidebar" aria-label="filters">
      <div className="side-search">
        <input
          ref={searchRef}
          className="search"
          type="search"
          value={filters.query}
          placeholder="search  /"
          aria-label="search tools and profiles"
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => onChange({ ...filters, query: e.target.value })}
        />
      </div>

      <div className="side-group">
        <span className="side-label">category</span>
        <ul className="side-list">
          <li>
            <button
              className={`side-item${filters.category === null ? " is-on" : ""}`}
              onClick={() => onChange({ ...filters, category: null })}
            >
              <span className="side-name">All</span>
              <span className="side-count">{total}</span>
            </button>
          </li>
          {categories.map((c) => (
            <li key={c}>
              <button
                className={`side-item${filters.category === c ? " is-on" : ""}`}
                onClick={() => onChange({ ...filters, category: filters.category === c ? null : c })}
              >
                <span className="side-name">{CATEGORY_LABEL[c]}</span>
                <span className="side-count">{byCategory.get(c)}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>

      <div className="side-group">
        <span className="side-label">state</span>
        <ul className="side-list">
          <li>
            <button
              className={`side-item${filters.state === null ? " is-on" : ""}`}
              onClick={() => onChange({ ...filters, state: null })}
            >
              <span className="side-name">All</span>
              <span className="side-count">{total}</span>
            </button>
          </li>
          {STATES.map((s: ConnectionState) => {
            const n = byState.get(s) ?? 0;
            return (
              <li key={s}>
                <button
                  className={`side-item${filters.state === s ? " is-on" : ""}${n === 0 ? " is-void" : ""}`}
                  onClick={() => onChange({ ...filters, state: filters.state === s ? null : s })}
                  disabled={n === 0}
                >
                  <span className={`state-dot state-${s}`} />
                  <span className="side-name">{STATE_LABEL[s]}</span>
                  <span className="side-count">{n}</span>
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </nav>
  );
});
