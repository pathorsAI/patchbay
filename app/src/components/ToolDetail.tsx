import { useEffect, useId, useMemo, useRef, useState } from "react";
import { expiryLevel, expiryText, expiryTitle } from "../expiry";
import { profileMatches } from "../filters";
import { metaEntries, rowKey, verdictText, type Panel, type SwitchNote } from "../panel";
import {
  isBlockingAdvisory,
  KEY_EXPIRY_LABEL,
  KEY_EXPIRY_LEVEL,
  sourceLabel,
  updateAvailable,
  type Advisory,
  type Note,
  type PermissionScope,
  type PermissionsReport,
  type Profile,
  type ToolStatus,
  type VersionInfo,
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
}: Readonly<{
  status: ToolStatus;
  panel: Panel;
  /** The board's search text; matching profiles are marked here too. */
  query: string;
  wantPermissions: boolean;
  onClose: () => void;
}>) {
  const report = panel.perms[status.tool];
  const note = panel.switchNotes[status.tool];

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

  // Opening a tool is the question. Answering it with "nobody has checked yet"
  // and a button is a question back, so every profile that has no verdict gets
  // checked on the way in — the click that opened the drawer *is* the consent
  // for the tier-2 call.
  //
  // Once per tool, not once per render: `verdicts` is keyed per row and is
  // never cleared by a board refresh, so a profile that has been checked (or is
  // being checked, which parks `null` in the map immediately) is skipped, and
  // the 30s poll cannot turn this into a loop. Re-checking on demand stays the
  // row's own button.
  useEffect(() => {
    for (const profile of status.profiles) {
      if (panel.verdicts[rowKey(status.tool, profile.id)] === undefined) {
        panel.verifyRow(status.tool, profile.id);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status.tool]);

  return (
    <>
      {/* Click-outside is a control, so it answers to the keyboard too — hence
          a real button rather than a div with an onClick. Same pattern as the
          key vault's drawer. */}
      <button type="button" className="scrim" aria-label="Close" onClick={onClose} />
      {/* Native <dialog> so the semantics come from the element. `open` rather
          than showModal(): the top layer would put the drawer above the scrim's
          own stacking and bring the UA's ::backdrop with it, and the panel
          already has a scrim. */}
      <dialog open className="detail" aria-label={`${status.tool} detail`}>
        <header className="detail-head">
          <ToolLogo tool={status.tool} size={28} />
          <div className="detail-title">
            <h2 className="tool">{status.tool}</h2>
            <span className="detail-sub">{subtitle(status)}</span>
          </div>
          <button type="button" className="action" onClick={onClose} aria-label="close">
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
          {note && <SwitchNoteBlock note={note} />}
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

        <PermissionsSection tool={status.tool} report={report} panel={panel} />

        {status.advisories.length > 0 && (
          <section className="section">
            <span className="field-key">advisories</span>
            <AdvisoryList advisories={status.advisories} />
          </section>
        )}

        {status.version && (
          <section className="section">
            <span className="field-key">version</span>
            <VersionRow version={status.version} />
          </section>
        )}

        {status.notes.length > 0 && (
          <section className="section">
            <span className="field-key">notes</span>
            <NoteList tool={status.tool} notes={status.notes} />
          </section>
        )}
      </dialog>
    </>
  );
}

function subtitle(status: ToolStatus): string {
  if (!status.installed) return "not installed";
  const n = status.profiles.length;
  return `${n} profile${n === 1 ? "" : "s"}`;
}

/**
 * The notes core attached to a tool or a permission report. Keyed by the text
 * itself — a note has no id, and its content is what makes it that note, so it
 * survives reordering in a way an array index does not.
 *
 * Loud notes first, and only the loud ones get a glyph: an `info` note keeps
 * the gutter (so every line still aligns) but draws nothing in it, because a
 * warning triangle on "docker has no active registry" is a lie about a tool
 * that is working.
 */
export function NoteList({ tool, notes }: Readonly<{ tool: string; notes: readonly Note[] }>) {
  const ordered = [...notes].sort((a, b) => RANK[b.kind] - RANK[a.kind]);
  return (
    <ul className="notes notes-full">
      {ordered.map((n) => (
        <li className={`note-${n.kind}`} key={`${tool}:${n.kind}:${n.text}`}>
          <NoteGlyph kind={n.kind} />
          {/* Clamped at six lines; the title carries anything longer, which is
              the same bargain the card's notes already strike. */}
          <span title={n.text}>{n.text}</span>
        </li>
      ))}
    </ul>
  );
}

const RANK: Record<Note["kind"], number> = { problem: 2, warn: 1, info: 0 };

/** The gutter is always there so the text edges line up; only the loud kinds
 *  put anything in it. */
export function NoteGlyph({ kind }: Readonly<{ kind: Note["kind"] }>) {
  if (kind === "info") return <span className="glyph glyph-info" aria-hidden="true" />;
  return (
    <span className={`glyph glyph-${kind}`} title={kind === "problem" ? "problem" : "warning"}>
      {kind === "problem" ? "\u25B2" : "\u25B3"}
    </span>
  );
}

/**
 * Curated notices: this tool was renamed, removed, or is unmaintained. Core has
 * always shipped these and the CLI has always shown them; the panel dropped
 * them on the floor by not declaring the field, which meant a *removed* tool
 * looked exactly like a healthy one.
 *
 * Above the notes, because an advisory outranks any caveat about your login:
 * there is no point fixing a credential for a CLI that no longer exists.
 */
function AdvisoryList({ advisories }: Readonly<{ advisories: readonly Advisory[] }>) {
  return (
    <ul className="advisories">
      {advisories.map((a) => (
        <li className={isBlockingAdvisory(a) ? "advisory is-blocking" : "advisory"} key={a.message}>
          <span className="advisory-kind">{a.kind.kind}</span>
          <span className="advisory-text">
            {a.message}
            {a.url && (
              <>
                {" "}
                <a href={a.url} target="_blank" rel="noreferrer noopener">
                  source
                </a>
              </>
            )}
          </span>
        </li>
      ))}
    </ul>
  );
}

/**
 * What is installed, and whether something newer exists.
 *
 * The board deliberately shows a version only when it is behind — 23 rows of
 * version numbers drown the one that matters. A drawer holds one tool, so the
 * installed version is context rather than noise and is always shown.
 *
 * `latest: null` is not "up to date": the update line only appears when both
 * versions are known and differ, and `note` explains an absence in the same
 * quiet register as the rest of the section. The update command is offered as
 * a copyable rather than a button because upgrading is a mutation of the
 * machine, not a read patchbay should make on its own.
 */
function VersionRow({ version }: Readonly<{ version: VersionInfo }>) {
  const behind = updateAvailable(version);
  return (
    <div className="dversion">
      <span className="dversion-line">
        <span className="dversion-num">{version.installed ?? "not installed"}</span>
        {behind && (
          <>
            <span className="dversion-arrow">→</span>
            <span className="dversion-num is-latest">{version.latest}</span>
          </>
        )}
        {/* An unknown source says nothing about where the tool came from, so
            it earns no chip — the note below already explains the gap. */}
        {version.source !== "unknown" && (
          <span className="chip chip-scope">{sourceLabel(version.source)}</span>
        )}
      </span>
      {version.note && <span className="muted small">{version.note}</span>}
      {behind && version.update_command && <Copyable text={version.update_command} />}
    </div>
  );
}

function SwitchNoteBlock({ note }: Readonly<{ note: SwitchNote }>) {
  // Execution being off is patchbay's own configuration. Quiet line, plus the
  // command you can run yourself — never the "last resort" lecture below,
  // which is about a shell variable no child process can reach.
  if (note.execDisabled) {
    return (
      <div className="switch-note">
        <span>{note.text}</span>
        {note.hint && <Copyable text={note.hint} />}
      </div>
    );
  }
  if (!note.hint) {
    return (
      <div className={`switch-note${note.bad ? " bad" : ""}`}>
        <span>{note.text}</span>
      </div>
    );
  }
  // The one case the panel genuinely cannot do for you: this kind of switch is
  // an environment variable in *your* shell, and no child process can reach
  // back and set it. So say that plainly, then hand over the line — a copyable
  // command is a last resort here, not the panel's answer to things it could
  // have run.
  return (
    <div className="last-resort">
      <span className="last-resort-why">
        {note.text} patchbay cannot reach back into the shell that launched it.
      </span>
      <Copyable text={note.hint} />
    </div>
  );
}

/**
 * States what it knows, then offers the action that gets more. The button is
 * always here, for every tool: whether patchbay can answer is the backend's
 * fact to report, not a list kept in the frontend that goes stale the moment a
 * probe learns a new trick. A tool with no reader comes back `supported:
 * false` and its notes say why — which is more than a hidden button ever did.
 *
 * Where a tool grants per resource rather than per credential, the read is
 * only half the surface: the other half is choosing *what* to read against.
 */
function PermissionsSection({
  tool,
  report,
  panel,
}: Readonly<{ tool: string; report: PermissionsReport | null | undefined; panel: Panel }>) {
  const loading = report === null;
  const scopes = panel.permScopes[tool];
  const [picked, setPicked] = useState<string | null>(null);

  // The scope in the box: what you chose, else the one this tool is already
  // configured for, else the first. Never nothing while there is a list.
  const chosen =
    picked ?? scopes?.find((s) => s.active)?.id ?? (scopes?.length ? scopes[0].id : null);

  // "re-read" only where something was read. A tool patchbay cannot answer for
  // says so, and offering to re-read that implies a second press could differ.
  let readLabel: string;
  if (loading) readLabel = "reading…";
  else if (report?.supported) readLabel = "re-read scopes";
  else readLabel = "read scopes";

  return (
    <section className="section">
      <span className="field-key">permissions</span>
      <div className="section-row">
        <button
          type="button"
          className="action"
          onClick={() => panel.loadPerms(tool)}
          disabled={loading}
        >
          {loading ? <span className="spinner" /> : null}
          {readLabel}
        </button>
        {report === undefined && (
          <span className="muted small">asks {tool} what this credential carries</span>
        )}
      </div>

      {/* Only once the backend has said this tool has scopes — which it only
          knows after the first read, because listing them execs the CLI too. */}
      {scopes && scopes.length > 0 && chosen && (
        <div className="perm-pick">
          <span className="muted small">
            granted per resource, not per credential — read another one
          </span>
          <div className="perm-pick-row">
            <ScopePicker scopes={scopes} value={chosen} onChange={setPicked} tool={tool} />
            <button
              type="button"
              className="action"
              onClick={() => panel.loadPerms(tool, chosen)}
              disabled={loading}
            >
              {loading ? <span className="spinner" /> : null}
              read
            </button>
          </div>
        </div>
      )}

      {report && (
        <div className="perm-body">
          {report.subject && (
            <div className="kv">
              <span className="kv-key">subject</span>
              <span className="kv-val">{report.subject}</span>
            </div>
          )}
          {/* Which resource this is about is part of the answer: "viewer" is a
              different fact about one project than about the next. */}
          {report.scope && (
            <div className="kv">
              <span className="kv-key">scope</span>
              <span className="kv-val">{report.scope}</span>
            </div>
          )}
          <Scopes report={report} />
          {report.notes.length > 0 && <NoteList tool={tool} notes={report.notes} />}
          {report.hint && <Copyable text={report.hint} />}
        </div>
      )}
    </section>
  );
}

/**
 * Type to filter, arrow to move, enter to take it — the app has no select and
 * no combobox, and a native `<select>` is unusable at the length these lists
 * reach (a working Google account sees dozens of projects). So: a text input
 * that filters a listbox, wired to the ARIA combobox pattern by hand.
 *
 * Escape closes the list and stops there. The drawer listens for Escape on the
 * window, and a keystroke that dismisses a dropdown must not also throw away
 * the pane you opened it in.
 */
function ScopePicker({
  scopes,
  value,
  onChange,
  tool,
}: Readonly<{
  scopes: readonly PermissionScope[];
  value: string;
  onChange: (id: string) => void;
  tool: string;
}>) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [cursor, setCursor] = useState(0);
  const boxRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const listId = useId();

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return scopes;
    return scopes.filter(
      (s) => s.id.toLowerCase().includes(q) || s.label.toLowerCase().includes(q),
    );
  }, [scopes, query]);

  // A filter that empties the list must not leave the cursor pointing past it.
  const at = matches.length === 0 ? -1 : Math.min(cursor, matches.length - 1);

  const close = () => {
    setOpen(false);
    setQuery("");
  };

  const take = (id: string) => {
    onChange(id);
    close();
  };

  // Clicking anywhere else is a dismissal, same as Escape.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!boxRef.current?.contains(e.target as Node)) close();
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  // Keyboard navigation is only navigation if the row you land on is visible.
  useEffect(() => {
    if (!open || at < 0) return;
    listRef.current
      ?.querySelector(`[data-idx="${at}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [open, at]);

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!open) {
        setOpen(true);
        return;
      }
      const step = e.key === "ArrowDown" ? 1 : -1;
      if (matches.length > 0) {
        setCursor((c) => (Math.min(c, matches.length - 1) + step + matches.length) % matches.length);
      }
    } else if (e.key === "Enter") {
      if (open && at >= 0) {
        e.preventDefault();
        take(matches[at].id);
      }
    } else if (e.key === "Escape") {
      if (open) {
        // The drawer's own Escape handler is on the window. Do not let it fire.
        e.preventDefault();
        e.stopPropagation();
        close();
      }
    } else if (e.key === "Tab") {
      close();
    }
  };

  return (
    <div className="combo" ref={boxRef}>
      <input
        type="text"
        className="field-input combo-input"
        role="combobox"
        aria-expanded={open}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={open && at >= 0 ? `${listId}-${at}` : undefined}
        aria-label={`scope to read ${tool} permissions in`}
        value={open ? query : value}
        placeholder={value}
        onChange={(e) => {
          setQuery(e.target.value);
          setCursor(0);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={onKeyDown}
      />
      {open && (
        <ul className="combo-list" id={listId} ref={listRef} role="listbox">
          {matches.length === 0 && <li className="combo-empty muted small">no match</li>}
          {matches.map((s, i) => (
            <li key={s.id}>
              {/* An option you can click is a button; the role puts it back
                  into the listbox for anyone reading it as one. */}
              <button
                type="button"
                id={`${listId}-${i}`}
                data-idx={i}
                role="option"
                aria-selected={s.id === value}
                className={`combo-opt${i === at ? " is-on" : ""}`}
                // mousedown, not click: blur would close the list first.
                onMouseDown={(e) => {
                  e.preventDefault();
                  take(s.id);
                }}
                onMouseEnter={() => setCursor(i)}
              >
                <span className="combo-opt-id">{s.id}</span>
                {s.label !== s.id && <span className="combo-opt-label">{s.label}</span>}
                {s.active && <span className="active-tag">active</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Scopes({ report }: Readonly<{ report: PermissionsReport }>) {
  if (!report.supported) return <p className="muted small">not supported for this tool</p>;
  if (report.scopes.length === 0) return <p className="muted small">the tool reported no scopes</p>;
  return (
    <div className="scopes">
      {report.scopes.map((s) => (
        <span className="chip chip-scope" key={s}>
          {s}
        </span>
      ))}
    </div>
  );
}

function ProfileRow({
  profile,
  active,
  matched,
  tool,
  panel,
}: Readonly<{
  profile: Profile;
  active: boolean;
  matched: boolean;
  tool: string;
  panel: Panel;
}>) {
  const entries = metaEntries(profile.meta);
  const level = expiryLevel(profile.expiry, panel.now);
  const key = rowKey(tool, profile.id);
  const busy = panel.switching === key;

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

  const classes = [
    "dprofile",
    active && "is-active",
    matched && "is-match",
    armed && "is-armed",
    busy && "is-busy",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <li className={classes}>
      {/* The row's information *is* the switch target, so the body is a real
          <button> — which is also why everything inside it is phrasing content
          (spans rather than <div>/<dl>): a button may not contain flow content,
          and the classes carry the layout either way. The two affordances in
          the foot are separate buttons and live outside it, so nothing
          interactive is nested inside anything else interactive. */}
      <button
        type="button"
        className="dprofile-body"
        disabled={!armed || blocked}
        aria-label={armed ? `switch ${tool} to ${profile.label}` : undefined}
        onClick={go}
      >
        <span className="dprofile-head">
          <span className="dprofile-label" title={profile.id}>
            {profile.label}
          </span>
          {matched && <span className="match-tag">match</span>}
          <span className={`chip chip-${level}`} title={expiryTitle(profile.expiry)}>
            {expiryText(profile.expiry, panel.now)}
          </span>
          {active && <span className="active-tag">active</span>}
        </span>
        {profile.label !== profile.id && <span className="dprofile-id">{profile.id}</span>}
        {entries.length > 0 && (
          <span className="kvs">
            {entries.map(([k, v]) => (
              <span className="kv" key={k}>
                <span className="kv-key">{k}</span>
                <span className="kv-val">{v}</span>
              </span>
            ))}
          </span>
        )}
      </button>

      <ProfileFoot tool={tool} profile={profile} armed={armed} busy={busy} blocked={blocked} go={go} panel={panel} />
    </li>
  );
}

function ProfileFoot({
  tool,
  profile,
  armed,
  busy,
  blocked,
  go,
  panel,
}: Readonly<{
  tool: string;
  profile: Profile;
  armed: boolean;
  busy: boolean;
  blocked: boolean;
  go: () => void;
  panel: Panel;
}>) {
  const verdict = panel.verdicts[rowKey(tool, profile.id)];
  const verifying = verdict === null;
  // patchbay's own execution switch, not anything about this login. Pressing
  // again cannot help, so the button says so by going grey — this used to
  // arrive as a note in the list, which put patchbay's internals in front of
  // the user as though their credentials were at fault.
  const cannotExec = verdict?.result === "exec_disabled";
  const switchOff = panel.switchNotes[tool]?.execDisabled ?? false;
  const EXEC_OFF_TITLE = "patchbay is running with command execution switched off";

  let verifyLabel: string;
  if (verifying) verifyLabel = "checking…";
  else if (verdict) verifyLabel = "re-check";
  else verifyLabel = "verify";

  return (
    <div className="dprofile-foot">
      <button
        type="button"
        className="row-action"
        onClick={() => panel.verifyRow(tool, profile.id)}
        disabled={verifying || cannotExec}
        title={cannotExec ? EXEC_OFF_TITLE : undefined}
      >
        {verifying ? <span className="spinner" /> : null}
        {verifyLabel}
      </button>

      {/* idle → running → result, and the result stays until the next
          refresh. Never a raw error dump: `verdictText` is core's sentence. */}
      {verdict && (
        <span className={`row-verdict verdict-${verdict.result}`} title={verdictText(verdict)}>
          <span className="mark">{verdictMark(verdict.result)}</span>
          {verdictText(verdict)}
        </span>
      )}

      {armed && (
        <button
          type="button"
          className="row-switch"
          onClick={go}
          disabled={blocked || switchOff}
          title={switchOff ? EXEC_OFF_TITLE : undefined}
        >
          {busy ? (
            <>
              <span className="spinner" />
              {" switching…"}
            </>
          ) : (
            <>
              switch <span className="switch-arrow">→</span>
            </>
          )}
        </button>
      )}
    </div>
  );
}

function verdictMark(result: string): string {
  if (result === "valid") return "✓";
  if (result === "invalid") return "✗";
  return "—";
}
