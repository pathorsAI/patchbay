import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { mcpAdd, mcpCopy, mcpReadSpec, mcpRemove } from "../api";
import {
  isWritableScope,
  type McpClient,
  type McpCopyReport,
  type McpServerEntry,
  type McpSpec,
  type McpTransportKind,
  type McpWriteReport,
} from "../types";

/**
 * The drawer that writes MCP config: one server, one client's copy of it at a
 * time, with an explicit save.
 *
 * Two things about this shape are load-bearing.
 *
 * **One client's copy, never "the server".** The matrix makes six clients look
 * like one row, but each of them has its own file with its own idea of what
 * that server is — Cursor's copy can point at a different command than Codex's,
 * and pretending otherwise would let a save silently flatten the difference.
 * So the form always shows exactly one client's entry, says whose, and a save
 * writes that one file.
 *
 * **Values live here and nowhere else.** `mcp_list`, which fills the matrix and
 * is refetched after every write, is value-free: names of env vars and headers,
 * a count of arguments. The secrets — a bearer token in a header, a key in
 * `env`, a `--api-key=…` argument — are fetched by `mcpReadSpec` only when a
 * drawer opens on one named server, live in this component's form state, and go
 * back out through `mcpAdd`. Nothing here may put them in the list state, and
 * nothing may log them.
 *
 * Editing is spelled as an overwriting add because core has exactly one write
 * path, and it is the one with the rolling backup, the parse–modify–serialize
 * round trip and the atomic rename.
 */
export function McpServerDetail({
  mode,
  name: serverName,
  clients,
  onClose,
  refresh,
  onGone,
}: Readonly<{
  mode: "add" | "edit";
  /** The server being edited. Ignored, and unused, in add mode. */
  name: string;
  clients: McpClient[];
  onClose: () => void;
  /** Re-read the matrix; resolves with the fresh list so callers can look. */
  refresh: () => Promise<McpClient[]>;
  /** The drawer removed the last copy and is closing — say so out there. */
  onGone: (text: string) => void;
}>) {
  const [name, setName] = useState(mode === "add" ? "" : serverName);
  const [form, setForm] = useState<Form>(EMPTY_FORM);
  /** The spec as it was loaded, to tell "edited" from "just looked at". */
  const [baseline, setBaseline] = useState(EMPTY_SPEC);
  const [targets, setTargets] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  /** An action parked behind the "discard changes?" confirm. */
  const [pending, setPending] = useState<{ what: string; run: () => void } | null>(null);

  /** Every client that has this server, in whatever scope. */
  const holders = useMemo(
    () => (mode === "edit" ? clients.filter((c) => entriesFor(c, serverName).length > 0) : []),
    [clients, mode, serverName],
  );
  const [source, setSource] = useState(() => pickSource(holders, serverName));

  const sourceEntries = useMemo(
    () => entriesFor(holders.find((c) => c.client === source), serverName),
    [holders, source, serverName],
  );
  /** A Claude Code entry under `projects.<path>` is read-only: core will not
   *  write that scope, so the panel must not offer a form for it. */
  const editable = mode === "add" || sourceEntries.some(isWritableScope);

  // Starts true in edit mode: the fetch is fired by an effect, and a frame of
  // the previous client's values under the new client's name would be a lie.
  const [loading, setLoading] = useState(mode === "edit");
  const [loadError, setLoadError] = useState<string | null>(null);

  // Values arrive here and only here: one server, one client, because a drawer
  // was opened on it.
  useEffect(() => {
    if (mode !== "edit" || !editable) {
      // A project-scope copy has nothing to fetch — core will not read it out
      // and the drawer explains why instead of spinning.
      setLoading(false);
      return;
    }
    let live = true;
    setLoading(true);
    setLoadError(null);
    mcpReadSpec(source, serverName)
      .then((spec) => {
        if (!live) return;
        const loaded = formOf(spec);
        setForm(loaded);
        setBaseline(fingerprint(loaded));
      })
      .catch((e) => live && setLoadError(String(e)))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [mode, editable, source, serverName]);

  const dirty =
    mode === "add"
      ? name.trim().length > 0 || fingerprint(form) !== EMPTY_SPEC
      : editable && !loading && !loadError && fingerprint(form) !== baseline;

  /** Run `action`, unless there are unsaved edits to ask about first. */
  const guard = useCallback(
    (what: string, run: () => void) => {
      if (dirty) setPending({ what, run });
      else run();
    },
    [dirty],
  );

  const close = useCallback(() => guard("close this drawer", onClose), [guard, onClose]);

  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [close]);

  const blocked = blocker(mode, name, form, targets);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (blocked || busy) return;
    setBusy(true);
    setOutcome(null);
    const spec = specOf(form);
    try {
      if (mode === "add") {
        // Per client, so a name that is free in Cursor still lands there when
        // Codex already has one. `overwrite: false` — an add that quietly
        // replaces something is the thing core refuses to do.
        const rows: AddRow[] = [];
        for (const key of targets) {
          const label = clients.find((c) => c.client === key)?.label ?? key;
          try {
            rows.push({ label, report: await mcpAdd(key, name.trim(), spec, false) });
          } catch (err) {
            rows.push({ label, error: String(err) });
          }
        }
        setOutcome({ kind: "adds", rows });
        if (rows.some((r) => r.report)) await refresh();
      } else {
        const report = await mcpAdd(source, serverName, spec, true);
        setBaseline(fingerprint(form));
        setOutcome({ kind: "write", report });
        await refresh();
      }
    } catch (err) {
      setOutcome({ kind: "error", text: String(err) });
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setBusy(true);
    setOutcome(null);
    try {
      const report = await mcpRemove(source, serverName);
      const fresh = await refresh();
      const left = fresh.filter((c) => entriesFor(c, serverName).length > 0);
      if (left.length === 0) {
        onGone(
          `removed \`${serverName}\` from ${report.label} — that was the last copy, so the row ` +
            `is gone from the matrix` +
            (report.backup_path ? `. the file as it was is at ${report.backup_path}` : ""),
        );
        onClose();
        return;
      }
      setOutcome({ kind: "write", report });
      setSource(pickSource(left, serverName));
    } catch (err) {
      setOutcome({ kind: "error", text: String(err) });
    } finally {
      setBusy(false);
    }
  };

  const copyTo = async (target: string) => {
    setBusy(true);
    setOutcome(null);
    try {
      setOutcome({ kind: "copy", report: await mcpCopy(serverName, source, [target], false) });
      await refresh();
    } catch (err) {
      setOutcome({ kind: "error", text: String(err) });
    } finally {
      setBusy(false);
    }
  };

  const title = mode === "add" ? "add server" : serverName;

  return (
    <>
      {/* Same drawer idiom as the tool detail and the key vault: a real button
          for click-outside so it answers to the keyboard, and a held-open
          <dialog> rather than showModal() so the panel's own scrim stays the
          one wash over the board. */}
      <button type="button" className="scrim" aria-label="Close" onClick={close} />
      <dialog open className="detail" aria-label={mode === "add" ? "add an MCP server" : `${serverName} detail`}>
        <header className="detail-head">
          <div className="detail-title">
            <h2 className="tool">{title}</h2>
            <span className="detail-sub">
              {mode === "add"
                ? "written to each client you pick"
                : `in ${holders.length} of ${clients.length} clients`}
            </span>
          </div>
          <button type="button" className="action" onClick={close} aria-label="close">
            close
          </button>
        </header>

        {pending && (
          <div className="confirm confirm-standalone">
            <span className="confirm-why">
              Unsaved changes. Discard them and {pending.what}?
            </span>
            <button type="button" className="row-action" onClick={() => setPending(null)}>
              keep editing
            </button>
            <button
              type="button"
              className="row-danger"
              onClick={() => {
                const { run } = pending;
                setPending(null);
                run();
              }}
            >
              discard
            </button>
          </div>
        )}

        {mode === "edit" && (
          <ClientPicker
            holders={holders}
            name={serverName}
            source={source}
            onPick={(key) => guard(`switch to the ${labelOf(holders, key)} copy`, () => setSource(key))}
          />
        )}

        <form className="detail-form" onSubmit={(e) => void save(e)}>
          {mode === "add" && (
            <>
              <label className="field">
                <span className="field-key">name</span>
                <input
                  className="field-input"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="context7"
                  autoFocus
                  spellCheck={false}
                  autoCapitalize="off"
                  autoCorrect="off"
                />
                <span className="muted small">
                  the key clients file it under — spaces are fine, control characters are not
                </span>
              </label>

              {/* A div rather than a fieldset: the panel's `.field` is a flex
                  column and a fieldset's legend does not sit in one properly.
                  Each checkbox carries its own <label>, so nothing is lost. */}
              <div className="field">
                <span className="field-key">write to</span>
                {clients.map((c) => (
                  <label className="check" key={c.client}>
                    <input
                      type="checkbox"
                      checked={targets.includes(c.client)}
                      onChange={(e) =>
                        setTargets((t) =>
                          e.target.checked ? [...t, c.client] : t.filter((k) => k !== c.client),
                        )
                      }
                    />
                    <span>
                      {c.label}{" "}
                      <span className="muted">
                        {c.present ? c.config_path : `${c.config_path} — will be created`}
                      </span>
                    </span>
                  </label>
                ))}
              </div>
            </>
          )}

          {!editable && sourceEntries.length > 0 && <ProjectScopeNote entries={sourceEntries} />}

          {loading && <p className="placeholder small">reading this client's copy…</p>}

          {loadError && (
            <div className="banner">
              <span className="glyph">△</span>
              <span>{loadError}</span>
            </div>
          )}

          {editable && !loading && !loadError && (
            <>
              <div className="field">
                <span className="field-key">transport</span>
                <div className="segmented">
                  {(["stdio", "http", "sse"] as McpTransportKind[]).map((t) => (
                    <button
                      type="button"
                      key={t}
                      className={`segment${form.transport === t ? " is-on" : ""}`}
                      aria-pressed={form.transport === t}
                      onClick={() => setForm((f) => ({ ...f, transport: t }))}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>

              {form.transport === "stdio" ? (
                <>
                  <label className="field">
                    <span className="field-key">command</span>
                    <input
                      className="field-input"
                      value={form.command}
                      onChange={(e) => setForm((f) => ({ ...f, command: e.target.value }))}
                      placeholder="npx"
                      spellCheck={false}
                      autoCapitalize="off"
                      autoCorrect="off"
                    />
                  </label>
                  <ValueRows
                    label="args"
                    hint="one box per argument, in order — this is how the file stores them, so nothing has to be re-quoted"
                    rows={form.args}
                    onChange={(args) => setForm((f) => ({ ...f, args }))}
                  />
                </>
              ) : (
                <label className="field">
                  <span className="field-key">url</span>
                  <input
                    className="field-input"
                    value={form.url}
                    onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                    placeholder="https://mcp.example.com/sse"
                    spellCheck={false}
                    autoCapitalize="off"
                    autoCorrect="off"
                  />
                </label>
              )}

              <PairRows
                label="env"
                hint="environment variables the entry sets"
                rows={form.env}
                onChange={(env) => setForm((f) => ({ ...f, env }))}
              />
              <PairRows
                label="headers"
                hint="sent with every request — http and sse only, and where bearer tokens live"
                rows={form.headers}
                onChange={(headers) => setForm((f) => ({ ...f, headers }))}
              />

              <div className="section-row">
                <button className="action" type="submit" disabled={busy || blocked !== null}>
                  {busy ? <span className="spinner" /> : null}
                  {saveLabel(mode, busy)}
                </button>
                {blocked ? (
                  <span className="muted small">{blocked}</span>
                ) : (
                  <span className="muted small">
                    {mode === "add"
                      ? `${targets.length} ${targets.length === 1 ? "file" : "files"}, backed up first`
                      : `writes ${labelOf(holders, source)}'s config, backed up first`}
                  </span>
                )}
              </div>
            </>
          )}
        </form>

        {outcome && <OutcomeBlock outcome={outcome} />}

        {mode === "edit" && (
          <>
            <CopySection
              clients={clients}
              name={serverName}
              source={source}
              sourceLabel={labelOf(holders, source)}
              editable={editable}
              busy={busy}
              onCopy={(key) => void copyTo(key)}
            />
            <RemoveSection
              // Remounts per client: a confirm armed for Cursor must not still
              // be armed after you switch the picker to Codex.
              key={source}
              label={labelOf(holders, source)}
              name={serverName}
              path={holders.find((c) => c.client === source)?.config_path ?? ""}
              busy={busy}
              onRemove={() => void remove()}
            />
          </>
        )}
      </dialog>
    </>
  );
}

/* -------------------------------------------------------------------------
   the form's own model
   ------------------------------------------------------------------------- */

/** A key/value row as the form holds it. Half-typed rows are legal here. */
type Pair = { k: string; v: string };

type Form = {
  transport: McpTransportKind;
  command: string;
  args: string[];
  url: string;
  env: Pair[];
  headers: Pair[];
};

const EMPTY_FORM: Form = {
  transport: "stdio",
  command: "",
  args: [],
  url: "",
  env: [],
  headers: [],
};

function formOf(spec: McpSpec): Form {
  // The other transport's fields stay in the form as blanks rather than being
  // dropped, so flipping the segmented control and back loses nothing typed.
  const rest = {
    env: spec.env.map(([k, v]) => ({ k, v })),
    headers: spec.headers.map(([k, v]) => ({ k, v })),
  };
  if (spec.transport === "stdio") {
    return { transport: "stdio", command: spec.command, args: [...spec.args], url: "", ...rest };
  }
  return { transport: spec.transport, command: "", args: [], url: spec.url, ...rest };
}

/**
 * The form as core wants it. Names are trimmed; **values never are** — a
 * secret with a trailing space is still that secret, and quietly editing it
 * would be a bug nobody could see. Blank rows are the leftovers of a `+` press
 * and are dropped.
 */
function specOf(form: Form): McpSpec {
  const both = {
    env: pairsOf(form.env),
    headers: pairsOf(form.headers),
  };
  if (form.transport === "stdio") {
    return {
      transport: "stdio",
      command: form.command.trim(),
      args: form.args.filter((a) => a.length > 0),
      ...both,
    };
  }
  if (form.transport === "http") return { transport: "http", url: form.url.trim(), ...both };
  return { transport: "sse", url: form.url.trim(), ...both };
}

const pairsOf = (rows: Pair[]): [string, string][] =>
  rows.filter((r) => r.k.trim().length > 0).map((r) => [r.k.trim(), r.v]);

/** What "unsaved changes" compares. Built from the spec, so adding an empty
 *  row or flipping to a transport and back is not an edit. */
const fingerprint = (form: Form): string => JSON.stringify(specOf(form));

const EMPTY_SPEC = fingerprint(EMPTY_FORM);

/**
 * Why Save is off, or null when it is on. Fail-fast in the form: core would
 * refuse all of these too, but after a write attempt and with the file already
 * backed up, which is a worse way to learn you left the command blank.
 */
function blocker(mode: "add" | "edit", name: string, form: Form, targets: string[]): string | null {
  if (mode === "add") {
    const trimmed = name.trim();
    if (!trimmed) return "give it a name";
    if (trimmed.length > 128) return "the name is longer than 128 characters";
    if (hasControlChar(trimmed)) return "the name contains a control character";
    if (targets.length === 0) return "pick at least one client to write to";
  }
  if (form.transport === "stdio") {
    if (!form.command.trim()) return "stdio needs a command";
  } else if (!form.url.trim()) {
    return `${form.transport} needs a url`;
  }
  return rowProblem(form.env, "env var") ?? rowProblem(form.headers, "header");
}

/** Core's one hard rule about names, checked by codepoint rather than by a
 *  regex full of escapes nobody can read. */
const hasControlChar = (s: string): boolean =>
  [...s].some((ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return code < 0x20 || code === 0x7f;
  });

function rowProblem(rows: Pair[], what: string): string | null {
  const seen = new Set<string>();
  for (const row of rows) {
    const key = row.k.trim();
    if (!key) {
      if (row.v.length > 0) return `one ${what} has a value but no name`;
      continue;
    }
    if (seen.has(key)) return `${what} \`${key}\` is listed twice`;
    seen.add(key);
  }
  return null;
}

function saveLabel(mode: "add" | "edit", busy: boolean): string {
  if (busy) return mode === "add" ? "writing…" : "saving…";
  return mode === "add" ? "add server" : "save";
}

/* -------------------------------------------------------------------------
   client selection
   ------------------------------------------------------------------------- */

const entriesFor = (client: McpClient | undefined, name: string): McpServerEntry[] =>
  client?.servers.filter((s) => s.name === name) ?? [];

/** Prefer a copy patchbay can actually write. */
function pickSource(holders: McpClient[], name: string): string {
  const writable = holders.find((c) => entriesFor(c, name).some(isWritableScope));
  return (writable ?? holders[0])?.client ?? "";
}

const labelOf = (clients: McpClient[], key: string): string =>
  clients.find((c) => c.client === key)?.label ?? key;

/**
 * Which client's copy is on screen. The chips are the honest part of the
 * drawer: six clients can each hold a different definition of the same name,
 * and this is where you find that out.
 */
function ClientPicker({
  holders,
  name,
  source,
  onPick,
}: Readonly<{
  holders: McpClient[];
  name: string;
  source: string;
  onPick: (key: string) => void;
}>) {
  return (
    <section className="section">
      <span className="field-key">editing</span>
      <div className="scopes">
        {holders.map((c) => {
          const writable = entriesFor(c, name).some(isWritableScope);
          return (
            <button
              type="button"
              key={c.client}
              className={`chip chip-pick${c.client === source ? " is-on" : ""}${writable ? "" : " is-proj"}`}
              aria-pressed={c.client === source}
              title={c.config_path}
              onClick={() => onPick(c.client)}
            >
              {c.label}
              {!writable && <span className="chip-tag">proj</span>}
            </button>
          );
        })}
      </div>
      <span className="muted small">
        each client keeps its own copy — this form shows one of them, and a save writes that one
        file
      </span>
    </section>
  );
}

/** The one case the drawer will not edit, said in full rather than by a
 *  greyed-out button. */
function ProjectScopeNote({ entries }: Readonly<{ entries: McpServerEntry[] }>) {
  const scopes = entries.map((e) => e.scope).filter(Boolean) as string[];
  const keys = [...entries.flatMap((e) => e.env_keys), ...entries.flatMap((e) => e.header_keys)];
  return (
    <div className="field">
      <div className="banner">
        <span className="glyph">△</span>
        <span>
          this copy lives in a project scope ({scopes.join(", ")}), not the user scope. patchbay
          only writes the user scope — a project's servers are that project's business. Edit it with{" "}
          <code>claude mcp</code> from that project, or by hand.
        </span>
      </div>
      {/* Value-free, straight off the matrix: what it is and the names of what
          it sets. Reading the values out of a scope patchbay will not write is
          not a thing this drawer needs to do. */}
      <span className="muted small">
        {entries.map(summaryOf).join(" · ")}
        {keys.length > 0 && ` · sets ${keys.join(", ")}`}
      </span>
    </div>
  );
}

const summaryOf = (e: McpServerEntry): string =>
  e.transport === "stdio" ? `stdio ${e.command} (${e.args_len})` : `${e.transport} ${e.url}`;

/* -------------------------------------------------------------------------
   repeated rows
   ------------------------------------------------------------------------- */

/** A list of single values — a stdio command's arguments, in file order. */
function ValueRows({
  label,
  hint,
  rows,
  onChange,
}: Readonly<{
  label: string;
  hint: string;
  rows: string[];
  onChange: (rows: string[]) => void;
}>) {
  return (
    <div className="field">
      <span className="field-key">{label}</span>
      {rows.map((value, i) => (
        // Keyed by position: these rows have no identity of their own, and
        // two arguments may legitimately be the same string.
        <div className="pair" key={i}>
          <input
            className="field-input"
            value={value}
            aria-label={`${label} ${i + 1}`}
            onChange={(e) => onChange(rows.map((r, j) => (j === i ? e.target.value : r)))}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
          />
          <button
            type="button"
            className="row-action"
            onClick={() => onChange(rows.filter((_, j) => j !== i))}
            aria-label={`remove ${label} ${i + 1}`}
          >
            −
          </button>
        </div>
      ))}
      <div className="section-row">
        <button type="button" className="row-action" onClick={() => onChange([...rows, ""])}>
          + {label}
        </button>
        <span className="muted small">{hint}</span>
      </div>
    </div>
  );
}

/** Name/value rows — env vars and headers. */
function PairRows({
  label,
  hint,
  rows,
  onChange,
}: Readonly<{
  label: string;
  hint: string;
  rows: Pair[];
  onChange: (rows: Pair[]) => void;
}>) {
  const set = (i: number, patch: Partial<Pair>) =>
    onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  return (
    <div className="field">
      <span className="field-key">{label}</span>
      {rows.map((row, i) => (
        // Keyed by position, as above.
        <div className="pair" key={i}>
          <input
            className="field-input pair-key"
            value={row.k}
            placeholder="NAME"
            aria-label={`${label} name ${i + 1}`}
            onChange={(e) => set(i, { k: e.target.value })}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
          />
          <input
            className="field-input"
            value={row.v}
            placeholder="value"
            aria-label={`${label} value ${i + 1}`}
            onChange={(e) => set(i, { v: e.target.value })}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            autoComplete="off"
          />
          <button
            type="button"
            className="row-action"
            onClick={() => onChange(rows.filter((_, j) => j !== i))}
            aria-label={`remove ${label} ${i + 1}`}
          >
            −
          </button>
        </div>
      ))}
      <div className="section-row">
        <button
          type="button"
          className="row-action"
          onClick={() => onChange([...rows, { k: "", v: "" }])}
        >
          + {label}
        </button>
        <span className="muted small">{hint}</span>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------
   copy and remove
   ------------------------------------------------------------------------- */

/**
 * The clients that do *not* have this server, each with the one action that
 * changes that. This is the whole reason the matrix exists — seeing that Cursor
 * is missing what Claude Code has is only useful if you can then fix it.
 */
function CopySection({
  clients,
  name,
  source,
  sourceLabel,
  editable,
  busy,
  onCopy,
}: Readonly<{
  clients: McpClient[];
  name: string;
  source: string;
  sourceLabel: string;
  editable: boolean;
  busy: boolean;
  onCopy: (key: string) => void;
}>) {
  // "Has it" means has it in a scope patchbay writes: a project-scope entry
  // does not stop a user-scope copy landing beside it, and core agrees.
  const missing = clients.filter(
    (c) => c.client !== source && !entriesFor(c, name).some(isWritableScope),
  );
  if (missing.length === 0) return null;

  return (
    <section className="section">
      <span className="field-key">copy elsewhere</span>
      {editable ? (
        <>
          <ul className="copy-list">
            {missing.map((c) => (
              <li key={c.client}>
                <span className="copy-label">{c.label}</span>
                <span className="copy-path">{c.config_path}</span>
                <button
                  type="button"
                  className="row-action"
                  disabled={busy}
                  onClick={() => onCopy(c.client)}
                >
                  copy here
                </button>
              </li>
            ))}
          </ul>
          <span className="muted small">
            copies the {sourceLabel} definition, values and all, translating the file format on the
            way
          </span>
        </>
      ) : (
        <span className="muted small">
          pick a copy patchbay can read first — a project-scope entry is not a source it will hand
          around
        </span>
      )}
    </section>
  );
}

/** Removing, behind the panel's one confirm idiom: in place, saying what it
 *  does and does not do, never pre-armed. */
function RemoveSection({
  label,
  name,
  path,
  busy,
  onRemove,
}: Readonly<{ label: string; name: string; path: string; busy: boolean; onRemove: () => void }>) {
  const [armed, setArmed] = useState(false);

  return (
    <section className="section">
      <span className="field-key">remove</span>
      {armed ? (
        <div className="confirm confirm-standalone">
          <span className="confirm-why">
            Remove <b>{name}</b> from {label}? It stops that client launching the server; the server
            itself and every other client's copy are untouched. {path} is backed up first.
          </span>
          <button
            type="button"
            className="row-action"
            onClick={() => setArmed(false)}
            disabled={busy}
          >
            cancel
          </button>
          <button type="button" className="row-danger" onClick={onRemove} disabled={busy}>
            {busy ? <span className="spinner" /> : null}
            {busy ? "removing…" : "remove"}
          </button>
        </div>
      ) : (
        <div className="section-row">
          <button
            type="button"
            className="row-action"
            onClick={() => setArmed(true)}
            disabled={busy}
          >
            remove from {label}
          </button>
        </div>
      )}
    </section>
  );
}

/* -------------------------------------------------------------------------
   what happened
   ------------------------------------------------------------------------- */

type AddRow = { label: string; report?: McpWriteReport; error?: string };

type Outcome =
  | { kind: "write"; report: McpWriteReport }
  | { kind: "copy"; report: McpCopyReport }
  | { kind: "adds"; rows: AddRow[] }
  | { kind: "error"; text: string };

function OutcomeBlock({ outcome }: Readonly<{ outcome: Outcome }>) {
  if (outcome.kind === "error") {
    // Core's sentence, unedited: it names the file, says what it refused and
    // what to do instead. Paraphrasing it would only ever lose something.
    return (
      <div className="banner">
        <span className="glyph">△</span>
        <span>{outcome.text}</span>
      </div>
    );
  }

  if (outcome.kind === "write") return <WriteBlock report={outcome.report} />;

  if (outcome.kind === "adds") {
    return (
      <section className="section">
        {outcome.rows.map((row) =>
          row.report ? (
            <WriteBlock key={row.label} report={row.report} />
          ) : (
            <div className="banner" key={row.label}>
              <span className="glyph">△</span>
              <span>
                {row.label}: {row.error}
              </span>
            </div>
          ),
        )}
      </section>
    );
  }

  const { report } = outcome;
  const carried = [...report.env_carried, ...report.header_carried];
  return (
    <section className="section">
      {/* Values travelled between files. Core reports which ones by name; not
          saying so would make a copy look cheaper than it is. */}
      {carried.length > 0 && (
        <div className="switch-note">
          <span>
            carried {carried.join(", ")} — the values went into the target files too, not just the
            names
          </span>
        </div>
      )}
      {report.written.map((w) => (
        <WriteBlock key={w.client} report={w} />
      ))}
    </section>
  );
}

function WriteBlock({ report }: Readonly<{ report: McpWriteReport }>) {
  return (
    <div className="switch-note">
      <span>
        wrote <b>{report.name}</b> to {report.label} — {report.config_path}
        {report.created_file && " (created)"}
        {report.backup_path && (
          <>
            <br />
            backup: {report.backup_path}
          </>
        )}
      </span>
      {report.notes.map((n) => (
        <span className="write-note" key={n}>
          <span className="glyph">△</span> {n}
        </span>
      ))}
    </div>
  );
}
