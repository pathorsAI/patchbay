import { headlineExpiry } from "../expiry";
import type { Panel } from "../panel";
import { isAlarming, STATE_LABEL, type ToolStatus } from "../types";
import { ExpiryChip } from "./Chip";
import { KeyGlyph } from "./Glyphs";
import { ToolLogo } from "./ToolLogo";

/**
 * One tool at a glance, in exactly three rows and a fixed height — the board
 * is a status surface, so every card must be the same shape and nothing on it
 * may wrap. Everything you can *do* to a tool lives in the detail view; the
 * card's only interaction is opening it.
 *
 * That single interaction is why the card is a real <button> rather than an
 * <article> wearing role="button": the focus ring, the Enter/Space handling and
 * the announced role all come from the element instead of being re-implemented
 * beside it. A button may only contain phrasing content, so the three rows are
 * spans rather than <header>/<h2>/<footer>. Nothing inside the card is itself
 * interactive, so the flattening costs nothing — and the `title` tooltips on
 * the badges keep working, which an absolutely-positioned overlay button would
 * have swallowed.
 */
export function ToolCard({ status, panel }: Readonly<{ status: ToolStatus; panel: Panel }>) {
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
  // Info notes are explanations, not complaints. Counting them here is what
  // put a warning triangle on tools that were working exactly as designed.
  const alarming = status.notes.filter(isAlarming);
  // Set only when this tool keeps no selection at all; carries the reason.
  const notApplicable =
    status.active_concept.kind === "not_applicable" ? status.active_concept.reason : null;
  const worst = alarming.some((n) => n.kind === "problem") ? "problem" : "warn";

  return (
    <button
      type="button"
      className={`card${status.installed ? "" : " card-absent"}`}
      onClick={() => panel.open(status.tool)}
      aria-label={`${status.tool}, ${STATE_LABEL[state]}`}
    >
      <span className="card-head">
        <ToolLogo tool={status.tool} size={20} />
        <span className="tool">{status.tool}</span>
        <span className={`state-dot state-${state}`} title={STATE_LABEL[state]} />
      </span>

      <span className="card-active">
        {/* A tool with no selection can still have a default worth naming —
            op's last sign-in, stripe's [default] table. The value shows; the
            tooltip is what says it is a default rather than a choice. */}
        {active && (
          <span
            className="active-id"
            title={notApplicable ? `${active.id} — ${notApplicable}` : active.id}
          >
            {active.label}
          </span>
        )}
        {/* An empty slot on rclone or docker is the right answer, not a
            missing one: those tools have no active anything. Saying "not
            connected" there was simply wrong. */}
        {!active && notApplicable && (
          <span className="active-id muted" title={notApplicable}>
            —
          </span>
        )}
        {!active && !notApplicable && (
          <span className="active-id muted">
            {status.installed ? "— not connected" : "— not installed"}
          </span>
        )}
      </span>

      <span className="card-foot">
        {/* No profiles means no credential to date — a "no expiry" chip there
            would read as a fact about a login that does not exist. */}
        {profiles > 0 && <ExpiryChip expiry={headlineExpiry(status)} now={panel.now} />}
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
        {alarming.length > 0 && (
          <span
            className={`warn-badge is-${worst}`}
            title={`${alarming.length} note${alarming.length === 1 ? "" : "s"} needing a look — open for detail`}
          >
            <span className={`glyph glyph-${worst}`}>{worst === "problem" ? "▲" : "△"}</span>
            {alarming.length}
          </span>
        )}
      </span>
    </button>
  );
}
