import { useEffect, useMemo, useState } from "react";
import { mcpList } from "../api";
import type { McpClient, McpServerEntry } from "../types";

/** What one client has to say about one server name. */
type Cell = "user" | "project" | "none";

function cellFor(entries: McpServerEntry[]): Cell {
  if (entries.length === 0) return "none";
  // A name can appear twice in Claude Code: once at user scope and once per
  // project. User scope wins the cell — it is the one that is always in force.
  return entries.some((e) => !e.scope?.startsWith("project:")) ? "user" : "project";
}

const MARK: Record<Cell, string> = { user: "✓", project: "proj", none: "—" };

/**
 * Which AI clients have which MCP servers. The matrix is the point: MCP config
 * is per-client and lives in six different files, so the only way to see that
 * Cursor is missing the server Claude Code has is to put them side by side.
 *
 * Clients that are not installed keep their column — an empty column is the
 * answer to "did I configure it there?", and hiding it would lose that.
 *
 * Read-only: `pb mcp add/copy/rm` does the writing. Transports show a command
 * or a URL and the *names* of env vars and headers, never their values.
 */
export function McpView() {
  const [clients, setClients] = useState<McpClient[] | null>(null);
  const [error, setError] = useState<string | null>(null);

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
      </div>

      {servers.length === 0 ? (
        <div className="empty">
          <p className="empty-line">no MCP servers registered</p>
          <p className="muted small vault-blurb">
            None of the {clients.length} clients patchbay knows about has a server configured.
          </p>
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
                  <tr key={name}>
                    <td className="cell-id">{name}</td>
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
              <li key={`${c.client}-${i}`}>
                <span className="glyph">△</span>
                <span>
                  {c.label}: {n}
                </span>
              </li>
            )),
          )}
        </ul>
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
