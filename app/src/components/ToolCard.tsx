import type { KeyboardEvent } from "react";
import { headlineExpiry } from "../expiry";
import type { Panel } from "../panel";
import { STATE_LABEL, type ToolStatus } from "../types";
import { ExpiryChip } from "./Chip";
import { KeyGlyph } from "./Glyphs";
import { ToolLogo } from "./ToolLogo";

/**
 * One tool at a glance, in exactly three rows and a fixed height — the board
 * is a status surface, so every card must be the same shape and nothing on it
 * may wrap. Everything you can *do* to a tool lives in the detail view; the
 * card's only interaction is opening it.
 */
export function ToolCard({ status, panel }: { status: ToolStatus; panel: Panel }) {
  const active = status.profiles.find((p) => p.id === status.active) ?? null;
  const state = status.connection_state;
  const profiles = status.profiles.length;
  const keys = status.registered_keys;
  // A vault key sitting beside this tool's login is a fact about the tool that
  // no probe can see, so it earns a mark of its own. Count only — the labels
  // and expiries are in the detail view, and the values are nowhere.
  const keysWanting = keys.filter(
    (k) => k.expiry_state === "expired" || k.expiry_state === "expiring_soon",
  ).length;

  const open = () => panel.open(status.tool);
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      open();
    }
  };

  return (
    <article
      className={`card${status.installed ? "" : " card-absent"}`}
      onClick={open}
      onKeyDown={onKey}
      role="button"
      tabIndex={0}
      aria-label={`${status.tool}, ${STATE_LABEL[state]}`}
    >
      <header className="card-head">
        <ToolLogo tool={status.tool} size={20} />
        <h2 className="tool">{status.tool}</h2>
        <span className={`state-dot state-${state}`} title={STATE_LABEL[state]} />
      </header>

      <div className="card-active">
        {active ? (
          <span className="active-id" title={active.id}>
            {active.label}
          </span>
        ) : (
          <span className="active-id muted">
            {status.installed ? "— not connected" : "— not installed"}
          </span>
        )}
      </div>

      <footer className="card-foot">
        {/* No profiles means no credential to date — a "no expiry" chip there
            would read as a fact about a login that does not exist. */}
        {profiles > 0 && <ExpiryChip expiresAt={headlineExpiry(status)} now={panel.now} />}
        <span className="card-count">
          {profiles} {profiles === 1 ? "profile" : "profiles"}
        </span>
        {keys.length > 0 && (
          <span
            className={`key-badge${keysWanting > 0 ? " is-warn" : ""}`}
            title={`${keys.length} registered key${keys.length === 1 ? "" : "s"}${
              keysWanting > 0 ? `, ${keysWanting} needing attention` : ""
            } — open for detail`}
          >
            <KeyGlyph size={10} />
            {keys.length}
          </span>
        )}
        {status.notes.length > 0 && (
          <span className="warn-badge" title={`${status.notes.length} note(s) — open for detail`}>
            <span className="glyph">△</span>
            {status.notes.length}
          </span>
        )}
      </footer>
    </article>
  );
}
