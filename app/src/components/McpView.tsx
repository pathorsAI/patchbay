import { useCallback, useEffect, useMemo, useState } from "react";
import { mcpList } from "../api";
import type { McpClient, McpServerEntry } from "../types";
import { McpServerDetail } from "./McpServerDetail";
import { NoteGlyph } from "./ToolDetail";

/** What one client has to say about one server name. */
type Cell = "user" | "project" | "none";

function cellFor(entries: McpServerEntry[]): Cell {
  if (entries.length === 0) return "none";
  // A name can appear twice in Claude Code: once at user scope and once per
  // project. User scope wins the cell — it is the one that is always in force.
  return entries.some((e) => !e.scope?.startsWith("project:")) ? "user" : "project";
}

const MARK: Record<Cell, string> = { user: "✓", project: "proj", none: "—" };

/** Which drawer is open, if any. */
type Open = { mode: "add" } | { mode: "edit"; name: string };

/**
 * Which AI clients have which MCP servers. The matrix is the point: MCP config
 * is per-client and lives in six different files, so the only way to see that
 * Cursor is missing the server Claude Code has is to put them side by side.
 *
 * Clients that are not installed keep their column — an empty column is the
 * answer to "did I configure it there?", and hiding it would lose that.
 *
 * The matrix itself stays value-free: a command or a URL, and the *names* of
 * env vars and headers, never their values. Values are read one server at a
 * time, by `McpServerDetail`, because a row was opened — see the note there.
 * Seeing the gap is only half of it, so a row is a way in: open it and you can
 * edit that client's copy, copy it to the clients that are missing it, or take
 * it out. `pb mcp add/copy/rm` still does the same work from a terminal.
 */
export function McpView() {
  const [clients, setClients] = useState<McpClient[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<Open | null>(null);
  /** The outcome of a write that outlived the drawer it happened in. */
  const [note, setNote] = useState<string | null>(null);

  /** Re-read the matrix. Resolves with the fresh list, which is what lets the
   *  drawer decide whether the server it was showing still exists. */
  const load = useCallback(async () => {
    const fresh = await mcpList();
    setClients(fresh);
    setError(null);
    return fresh;
  }, []);

  /** Open a drawer, and drop the last drawer's parting note with it. */
  const show = (next: Open) => {
    setNote(null);
    setOpen(next);
  };

  useEffect(() => {
    let live = true;
    mcpList()
      .then((c) => live && setClients(c))
      .catch((e) => live && setError(String(e)));
    return () => {
      live = false;
    };
  }, []);

  const servers = useMemo(() => {
    if (!clients) return [];
    const names = new Set<string>();
    for (const c of clients) for (const s of c.servers) names.add(s.name);
    return [...names].sort((a, b) => a.localeCompare(b));
  }, [clients]);

  if (error) {
    return (
      <div className="banner">
        <span className="glyph">△</span>
        <span>{error}</span>
      </div>
    );
  }

  if (!clients) return <p className="placeholder">reading client configs…</p>;

  const configured = clients.filter((c) => c.present).length;

  return (
    <div className="view">
      <div className="view-head">
        <h2 className="view-title">MCP clients</h2>
        <span className="view-sub">
          {servers.length} {servers.length === 1 ? "server" : "servers"} across {configured} of{" "}
          {clients.length} clients
        </span>
        <button type="button" className="action" onClick={() => show({ mode: "add" })}>
          add server
        </button>
      </div>

      {note && (
        <div className="switch-note">
          <span>{note}</span>
        </div>
      )}

      {servers.length === 0 ? (
        <div className="empty">
          <p className="empty-line">no MCP servers registered</p>
          <p className="muted small vault-blurb">
            None of the {clients.length} clients patchbay knows about has a server configured.
          </p>
          <button type="button" className="action" onClick={() => show({ mode: "add" })}>
            add server
          </button>
        </div>
      ) : (
        <div className="scroller">
          <table className="table table-mcp">
            <thead>
              <tr>
                <th>server</th>
                {clients.map((c) => (
                  <th
                    key={c.client}
                    className={`col-client${c.present ? "" : " is-absent"}`}
                    title={c.present ? c.config_path : `${c.config_path} (no config file)`}
                  >
                    {c.label}
                  </th>
                ))}
                <th>transport</th>
              </tr>
            </thead>
            <tbody>
              {servers.map((name) => {
                // Any client's copy will do for the transport column: they are
                // the same server, and the first one that has it is as good a
                // description as any.
                const spec = clients.flatMap((c) => c.servers).find((s) => s.name === name)!;
                return (
                  // The whole row opens the drawer, the way a board card does:
                  // the row's information *is* what you came to act on. A <tr>
                  // cannot be a button, so the name cell holds a real one for
                  // the keyboard; its click bubbles here and asks for the same
                  // thing twice, which costs nothing.
                  <tr key={name} className="row-open" onClick={() => show({ mode: "edit", name })}>
                    <td className="cell-id">
                      <button type="button" className="row-open-name">
                        {name}
                      </button>
                    </td>
                    {clients.map((c) => {
                      const cell = cellFor(c.servers.filter((s) => s.name === name));
                      return (
                        <td key={c.client} className={`cell-mark mark-${cell}`}>
                          {MARK[cell]}
                        </td>
                      );
                    })}
                    <td className="cell-mono cell-transport">{transportOf(spec)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="view-head view-head-sub">
        <h3 className="view-title small-title">Config paths</h3>
      </div>
      <ul className="paths">
        {clients.map((c) => (
          <li key={c.client} className={c.present ? "" : "is-absent"}>
            <span className="path-label">{c.label}</span>
            <span className="path-file">{c.config_path}</span>
            <span className="path-count">{serverCount(c)}</span>
          </li>
        ))}
      </ul>

      {clients.some((c) => c.notes.length > 0) && (
        <ul className="notes notes-full">
          {clients.flatMap((c) =>
            c.notes.map((n, i) => (
              <li className={`note-${n.kind}`} key={`${c.client}-${i}`}>
                <NoteGlyph kind={n.kind} />
                <span>
                  {c.label}: {n.text}
                </span>
              </li>
            )),
          )}
        </ul>
      )}

      {open && (
        <McpServerDetail
          // Remounts when the row changes, so no drawer ever shows one
          // server's form under another server's name.
          key={open.mode === "add" ? "add" : `edit:${open.name}`}
          mode={open.mode}
          name={open.mode === "edit" ? open.name : ""}
          clients={clients}
          onClose={() => setOpen(null)}
          refresh={load}
          onGone={setNote}
        />
      )}
    </div>
  );
}

function transportOf(s: McpServerEntry): string {
  if (s.transport === "stdio") {
    const base = s.command.split("/").pop() || s.command;
    return s.args_len === 0 ? `stdio ${base}` : `stdio ${base} (${s.args_len})`;
  }
  return `${s.transport} ${s.url}`;
}

/** "3 servers" for a client whose config exists, an em dash for one that does not. */
function serverCount(client: McpClient): string {
  if (!client.present) return "—";
  const n = client.servers.length;
  return `${n} server${n === 1 ? "" : "s"}`;
}
