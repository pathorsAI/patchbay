import { useEffect } from "react";
import { countdown, levelOf } from "../expiry";
import { profileMatches } from "../filters";
import { metaEntries, verdictText, type Panel } from "../panel";
import { PERMISSIONS_TOOLS, type Profile, type ToolStatus } from "../types";
import { Copyable } from "./Copyable";
import { ToolLogo } from "./ToolLogo";

/**
 * The operating surface for one tool: every profile with its own metadata and
 * expiry, the switch buttons, verify, permissions, and the notes in full —
 * nothing clamped, because this is where you read them.
 */
export function ToolDetail({
  status,
  panel,
  query,
  wantPermissions,
  onClose,
}: {
  status: ToolStatus;
  panel: Panel;
  /** The board's search text; matching profiles are marked here too. */
  query: string;
  wantPermissions: boolean;
  onClose: () => void;
}) {
  const verdict = panel.verdicts[status.tool];
  const report = panel.perms[status.tool];
  const note = panel.switchNotes[status.tool];
  const canAskPermissions = PERMISSIONS_TOOLS.has(status.tool);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Opened via a card's "permissions" button: fetch without a second click.
  useEffect(() => {
    if (wantPermissions && report === undefined) panel.loadPerms(status.tool);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wantPermissions, status.tool]);

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="detail" role="dialog" aria-label={`${status.tool} detail`}>
        <header className="detail-head">
          <ToolLogo tool={status.tool} size={28} />
          <div className="detail-title">
            <h2 className="tool">{status.tool}</h2>
            <span className="detail-sub">
              {status.installed ? `${status.profiles.length} profile${status.profiles.length === 1 ? "" : "s"}` : "not installed"}
            </span>
          </div>
          <button className="action" onClick={onClose} aria-label="close">
            close
          </button>
        </header>

        <section className="section">
          <span className="field-key">profiles</span>
          {status.profiles.length === 0 ? (
            <p className="placeholder small">
              {status.installed ? "no profiles found in this tool's local state" : "the tool is not on PATH"}
            </p>
          ) : (
            <ul className="dprofiles">
              {status.profiles.map((p) => (
                <ProfileRow
                  key={p.id}
                  profile={p}
                  active={p.id === status.active}
                  matched={profileMatches(p, query)}
                  tool={status.tool}
                  panel={panel}
                />
              ))}
            </ul>
          )}
          {note && (
            <div className={`switch-note${note.bad ? " bad" : ""}`}>
              <span>{note.text}</span>
              {note.hint && <Copyable text={note.hint} />}
            </div>
          )}
        </section>

        <section className="section">
          <span className="field-key">liveness</span>
          <div className="section-row">
            <button className="action" onClick={() => panel.verify(status.tool)} disabled={verdict === null}>
              {verdict === null ? <span className="spinner" /> : null}
              verify
            </button>
            {verdict === undefined && <span className="muted small">runs the tool's own CLI</span>}
          </div>
          {verdict && (
            <p className={`verdict-full verdict-${verdict.result}`}>
              <span className="mark">
                {verdict.result === "valid" ? "✓" : verdict.result === "invalid" ? "✗" : "—"}
              </span>
              {verdictText(verdict)}
            </p>
          )}
          {verdict?.result === "unsupported" && verdict.hint && <Copyable text={verdict.hint} />}
        </section>

        <section className="section">
          <span className="field-key">permissions</span>
          {!canAskPermissions ? (
            <p className="muted small">
              patchbay cannot report what this credential is allowed to do — permissions live server-side, per
              resource.
            </p>
          ) : (
            <>
              <div className="section-row">
                <button
                  className="action"
                  onClick={() => panel.loadPerms(status.tool)}
                  disabled={report === null}
                >
                  {report === null ? <span className="spinner" /> : null}
                  {report ? "re-read scopes" : "read scopes"}
                </button>
              </div>
              {report && (
                <div className="perm-body">
                  {report.subject && (
                    <div className="kv">
                      <span className="kv-key">subject</span>
                      <span className="kv-val">{report.subject}</span>
                    </div>
                  )}
                  {report.supported ? (
                    report.scopes.length ? (
                      <div className="scopes">
                        {report.scopes.map((s) => (
                          <span className="chip chip-scope" key={s}>
                            {s}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <p className="muted small">the tool reported no scopes</p>
                    )
                  ) : (
                    <p className="muted small">not supported for this tool</p>
                  )}
                  {report.notes.length > 0 && (
                    <ul className="notes notes-full">
                      {report.notes.map((n, i) => (
                        <li key={i}>
                          <span className="glyph">△</span>
                          <span>{n}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                  {report.hint && <Copyable text={report.hint} />}
                </div>
              )}
            </>
          )}
        </section>

        {status.notes.length > 0 && (
          <section className="section">
            <span className="field-key">notes</span>
            <ul className="notes notes-full">
              {status.notes.map((n, i) => (
                <li key={i}>
                  <span className="glyph">△</span>
                  <span>{n}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
      </aside>
    </>
  );
}

function ProfileRow({
  profile,
  active,
  matched,
  tool,
  panel,
}: {
  profile: Profile;
  active: boolean;
  matched: boolean;
  tool: string;
  panel: Panel;
}) {
  const entries = metaEntries(profile.meta);
  const level = levelOf(profile.expires_at, panel.now);
  const busy = panel.switching === `${tool}:${profile.id}`;

  return (
    <li className={`dprofile${active ? " is-active" : ""}${matched ? " is-match" : ""}`}>
      <div className="dprofile-head">
        <span className="dprofile-label" title={profile.id}>
          {profile.label}
        </span>
        {matched && <span className="match-tag">match</span>}
        <span className={`chip chip-${level}`}>{countdown(profile.expires_at, panel.now)}</span>
        {active ? (
          <span className="active-tag">active</span>
        ) : (
          <button
            className="switch always"
            onClick={() => panel.switchTo(tool, profile.id)}
            disabled={panel.switching !== null}
          >
            {busy ? "…" : "switch"}
          </button>
        )}
      </div>
      {profile.label !== profile.id && <div className="dprofile-id">{profile.id}</div>}
      {entries.length > 0 && (
        <dl className="kvs">
          {entries.map(([k, v]) => (
            <div className="kv" key={k}>
              <span className="kv-key">{k}</span>
              <span className="kv-val">{v}</span>
            </div>
          ))}
        </dl>
      )}
    </li>
  );
}
