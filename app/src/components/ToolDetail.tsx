import { useEffect, type KeyboardEvent } from "react";
import { countdown, levelOf } from "../expiry";
import { profileMatches } from "../filters";
import { metaEntries, rowKey, verdictText, type Panel } from "../panel";
import {
  KEY_EXPIRY_LABEL,
  KEY_EXPIRY_LEVEL,
  PERMISSIONS_TOOLS,
  type Profile,
  type ToolStatus,
} from "../types";
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
  const report = panel.perms[status.tool];
  const note = panel.switchNotes[status.tool];
  const hasScopeReader = PERMISSIONS_TOOLS.has(status.tool);

  useEffect(() => {
    // `globalThis.` because the React KeyboardEvent type is in scope here.
    const onKey = (e: globalThis.KeyboardEvent) => e.key === "Escape" && onClose();
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
          {note &&
            (note.hint ? (
              /* The one case the panel genuinely cannot do for you: this kind
                 of switch is an environment variable in *your* shell, and no
                 child process can reach back and set it. So say that plainly,
                 then hand over the line — a copyable command is a last resort
                 here, not the panel's answer to things it could have run. */
              <div className="last-resort">
                <span className="last-resort-why">
                  {note.text} patchbay cannot do this one for you: it changes a variable in the
                  shell that launched it, and a program cannot reach back into its parent shell.
                </span>
                <Copyable text={note.hint} />
              </div>
            ) : (
              <div className={`switch-note${note.bad ? " bad" : ""}`}>
                <span>{note.text}</span>
              </div>
            ))}
        </section>

        {/* Vault keys that belong beside this tool's login. Metadata only —
            label, last 4, expiry. The values are in the OS keychain and the
            panel has no command that returns one. */}
        {status.registered_keys.length > 0 && (
          <section className="section">
            <span className="field-key">registered keys</span>
            <ul className="dkeys">
              {status.registered_keys.map((k) => (
                <li className="dkey" key={k.id}>
                  <span className="dkey-label" title={k.id}>
                    {k.label}
                  </span>
                  <span className="dkey-last4" title="last 4 characters of the secret">
                    ··{k.last4}
                  </span>
                  <span
                    className={`chip chip-${KEY_EXPIRY_LEVEL[k.expiry_state]}`}
                    title={k.expires_at ?? "no expiry recorded"}
                  >
                    {KEY_EXPIRY_LABEL[k.expiry_state]}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        )}

        <section className="section">
          <span className="field-key">permissions</span>
          {/* States what it knows, then offers the action that gets more. The
              button is always here: even where patchbay has no scope reader,
              asking and reporting the answer beats a sentence that just says
              no and gives you nothing to press. */}
          <div className="section-row">
            <button
              className="action"
              onClick={() => panel.loadPerms(status.tool)}
              disabled={report === null}
            >
              {report === null ? <span className="spinner" /> : null}
              {report === null ? "reading…" : report ? "re-read scopes" : "read scopes"}
            </button>
            {report === undefined && (
              <span className="muted small">
                {hasScopeReader
                  ? `asks ${status.tool} what this credential carries`
                  : `no scope reader for ${status.tool} yet — most permissions live server-side, per resource`}
              </span>
            )}
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
  const key = rowKey(tool, profile.id);
  const busy = panel.switching === key;
  const verdict = panel.verdicts[key];
  const verifying = verdict === null;

  // Switching is the whole point of a profile row, so the row *is* the button.
  // A 60px target next to a 380px row of the same information reads as the
  // less important thing, and it is not — it is the only thing you can do here.
  // The active row has nothing to switch to, so it stays inert.
  const armed = !active;
  const blocked = panel.switching !== null;

  const go = () => {
    if (!armed || blocked) return;
    panel.switchTo(tool, profile.id);
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      go();
    }
  };

  return (
    <li
      className={`dprofile${active ? " is-active" : ""}${matched ? " is-match" : ""}${
        armed ? " is-armed" : ""
      }${busy ? " is-busy" : ""}`}
    >
      {/* The row's information *is* the switch target. The two affordances in
          the foot are real buttons and live outside it, so nothing interactive
          is nested inside anything else interactive. */}
      <div
        className="dprofile-body"
        role={armed ? "button" : undefined}
        tabIndex={armed ? 0 : undefined}
        aria-label={armed ? `switch ${tool} to ${profile.label}` : undefined}
        aria-disabled={armed && blocked ? true : undefined}
        onClick={armed ? go : undefined}
        onKeyDown={armed ? onKey : undefined}
      >
        <div className="dprofile-head">
          <span className="dprofile-label" title={profile.id}>
            {profile.label}
          </span>
          {matched && <span className="match-tag">match</span>}
          <span className={`chip chip-${level}`}>{countdown(profile.expires_at, panel.now)}</span>
          {active && <span className="active-tag">active</span>}
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
      </div>

      <div className="dprofile-foot">
        <button
          className="row-action"
          onClick={() => panel.verifyRow(tool, profile.id)}
          disabled={verifying}
        >
          {verifying ? <span className="spinner" /> : null}
          {verifying ? "checking…" : verdict ? "re-check" : "verify"}
        </button>

        {/* idle → running → result, and the result stays until the next
            refresh. Never a raw error dump: `verdictText` is core's sentence. */}
        {verdict && (
          <span className={`row-verdict verdict-${verdict.result}`} title={verdictText(verdict)}>
            <span className="mark">
              {verdict.result === "valid" ? "✓" : verdict.result === "invalid" ? "✗" : "—"}
            </span>
            {verdictText(verdict)}
          </span>
        )}

        {armed && (
          <button className="row-switch" onClick={go} disabled={blocked}>
            {busy ? (
              <>
                <span className="spinner" />
                switching…
              </>
            ) : (
              <>
                switch <span className="switch-arrow">→</span>
              </>
            )}
          </button>
        )}
      </div>
    </li>
  );
}
