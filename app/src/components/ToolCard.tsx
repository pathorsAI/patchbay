import type { KeyboardEvent, MouseEvent } from "react";
import { metaLine, verdictText, type Panel } from "../panel";
import { PERMISSIONS_TOOLS, type ToolStatus } from "../types";
import { ExpiryChip } from "./Chip";
import { Copyable } from "./Copyable";
import { ToolLogo } from "./ToolLogo";

/** Buttons inside the card act on the tool; they must not also open it. */
function stop(e: MouseEvent) {
  e.stopPropagation();
}

/**
 * One tool at a glance. The card is the overview — the whole surface opens the
 * tool's detail view, where the full profile list and the actions live.
 */
export function ToolCard({ status, panel }: { status: ToolStatus; panel: Panel }) {
  const { now } = panel;
  const active = status.profiles.find((p) => p.id === status.active) ?? null;
  const others = status.profiles.filter((p) => p.id !== status.active);
  const verdict = panel.verdicts[status.tool];
  const note = panel.switchNotes[status.tool];
  const meta = active ? metaLine(active.meta) : "";

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
      aria-label={`${status.tool} details`}
    >
      <header className="card-head">
        <ToolLogo tool={status.tool} size={20} />
        <h2 className="tool">{status.tool}</h2>
        <span className={`installed ${status.installed ? "yes" : "no"}`}>
          {status.installed ? <span className="dot" /> : "not installed"}
        </span>
      </header>

      {active ? (
        <div className="active">
          <div className="active-top">
            <span className="active-id" title={active.id}>
              {active.label}
            </span>
            <ExpiryChip expiresAt={active.expires_at} now={now} />
          </div>
          {meta && <div className="active-meta">{meta}</div>}
        </div>
      ) : (
        <div className="active active-none">
          {status.profiles.length ? "no active profile" : "nothing logged in"}
        </div>
      )}

      {others.length > 0 && (
        <ul className="profiles">
          {others.map((p) => (
            <li className="prow" key={p.id}>
              <span className="prow-label" title={p.id}>
                {p.label}
              </span>
              <ExpiryChip expiresAt={p.expires_at} now={now} />
              <button
                className="switch"
                onClick={(e) => {
                  stop(e);
                  panel.switchTo(status.tool, p.id);
                }}
                disabled={panel.switching !== null}
                aria-label={`switch ${status.tool} to ${p.label}`}
              >
                {panel.switching === `${status.tool}:${p.id}` ? "…" : "switch"}
              </button>
            </li>
          ))}
        </ul>
      )}

      {note && (
        <div className={`switch-note${note.bad ? " bad" : ""}`} onClick={stop}>
          <span>{note.text}</span>
          {note.hint && <Copyable text={note.hint} />}
        </div>
      )}

      {status.notes.length > 0 && (
        <ul className="notes">
          {status.notes.map((n, i) => (
            <li key={i} title={n}>
              <span className="glyph">△</span>
              <span>{n}</span>
            </li>
          ))}
        </ul>
      )}

      <footer className="actions">
        <button
          className="action"
          onClick={(e) => {
            stop(e);
            panel.verify(status.tool);
          }}
          disabled={verdict === null}
        >
          {verdict === null ? <span className="spinner" /> : null}
          verify
        </button>
        {PERMISSIONS_TOOLS.has(status.tool) && (
          <button
            className="action"
            onClick={(e) => {
              stop(e);
              panel.open(status.tool, { permissions: true });
            }}
          >
            permissions
          </button>
        )}
        {verdict && (
          <span className={`verdict verdict-${verdict.result}`} title={verdictText(verdict)}>
            <span className="mark">
              {verdict.result === "valid" ? "✓" : verdict.result === "invalid" ? "✗" : "—"}
            </span>
            {verdictText(verdict)}
          </span>
        )}
      </footer>
    </article>
  );
}
