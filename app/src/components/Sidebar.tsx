import { forwardRef } from "react";
import type { Filters } from "../filters";
import { counts } from "../filters";
import type { View } from "../panel";
import { KeyGlyph, MatrixGlyph } from "./Glyphs";
import {
  categoriesPresent,
  categoryLabel,
  STATE_LABEL,
  STATES,
  type ConnectionState,
  type ToolStatus,
} from "../types";

interface Props {
  statuses: ToolStatus[];
  filters: Filters;
  onChange(next: Filters): void;
  view: View;
  onView(next: View): void;
}

/**
 * The board's index: search at the top, what a tool is in the middle, how it
 * is doing at the bottom. Category and state compose with AND; "All" in either
 * list clears that dimension only.
 *
 * Below a rule sit the two views that are not the board. They are a different
 * kind of thing from a filter — they replace the board rather than narrow it —
 * so they are separated rather than mixed into the lists above.
 */
export const Sidebar = forwardRef<HTMLInputElement, Props>(function Sidebar(
  { statuses, filters, onChange, view, onView },
  searchRef,
) {
  const { total, byCategory, byState } = counts(statuses, filters.query);
  // Derived from what the probes actually reported, not from a list in this
  // file: a category core adds tomorrow shows up here without a panel release,
  // and a machine with no payments CLI is not offered a Payments filter.
  const categories = categoriesPresent(byCategory.keys());

  // Clicking a filter while a side view is open means "show me the board",
  // otherwise the click would appear to do nothing.
  const filter = (next: Filters) => {
    onChange(next);
    onView("board");
  };
  const onBoard = view === "board";

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
              type="button"
              className={`side-item${onBoard && filters.category === null ? " is-on" : ""}`}
              onClick={() => filter({ ...filters, category: null })}
            >
              <span className="side-name">All</span>
              <span className="side-count">{total}</span>
            </button>
          </li>
          {categories.map((c) => (
            <li key={c}>
              <button
                type="button"
                className={`side-item${onBoard && filters.category === c ? " is-on" : ""}`}
                onClick={() => filter({ ...filters, category: filters.category === c ? null : c })}
              >
                <span className="side-name">{categoryLabel(c)}</span>
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
              type="button"
              className={`side-item${onBoard && filters.state === null ? " is-on" : ""}`}
              onClick={() => filter({ ...filters, state: null })}
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
                  type="button"
                  className={`side-item${onBoard && filters.state === s ? " is-on" : ""}${n === 0 ? " is-void" : ""}`}
                  onClick={() => filter({ ...filters, state: filters.state === s ? null : s })}
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

      <hr className="side-rule" />

      <div className="side-group">
        <ul className="side-list">
          <li>
            <button
              type="button"
              className={`side-item${view === "keys" ? " is-on" : ""}`}
              onClick={() => onView(view === "keys" ? "board" : "keys")}
              aria-pressed={view === "keys"}
            >
              <span className="side-glyph">
                <KeyGlyph />
              </span>
              <span className="side-name">Key vault</span>
            </button>
          </li>
          <li>
            <button
              type="button"
              className={`side-item${view === "mcp" ? " is-on" : ""}`}
              onClick={() => onView(view === "mcp" ? "board" : "mcp")}
              aria-pressed={view === "mcp"}
            >
              <span className="side-glyph">
                <MatrixGlyph />
              </span>
              <span className="side-name">MCP clients</span>
            </button>
          </li>
        </ul>
      </div>
    </nav>
  );
});
