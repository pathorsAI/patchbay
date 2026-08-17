import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import {
  permissions as fetchPerms,
  permissionScopes,
  permissionsIn,
  statusAll,
  switchProfile,
  verifyProfile,
} from "./api";
import { clockTime, summarize, summaryLine } from "./expiry";
import { apply, isFiltered, NO_FILTERS, type Filters } from "./filters";
import { rowKey, switchMessage, type Panel, type SwitchNote, type View } from "./panel";
import {
  categoryLabel,
  STATE_LABEL,
  type PermissionScope,
  type PermissionsReport,
  type ToolStatus,
  type VerifyOutcome,
} from "./types";
import { KeysView } from "./components/KeysView";
import { McpView } from "./components/McpView";
import { Sidebar } from "./components/Sidebar";
import { ToolCard } from "./components/ToolCard";
import { ToolDetail } from "./components/ToolDetail";
import { UpdateBanner } from "./components/UpdateBanner";

const POLL_MS = 30_000;
/** Countdowns must not go stale between polls. */
const TICK_MS = 10_000;

export default function App() {
  const [statuses, setStatuses] = useState<ToolStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshedAt, setRefreshedAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [version, setVersion] = useState("");
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [view, setView] = useState<View>("board");

  const [detail, setDetail] = useState<{ tool: string; permissions: boolean } | null>(null);
  const [verdicts, setVerdicts] = useState<Record<string, VerifyOutcome | null>>({});
  const [perms, setPerms] = useState<Record<string, PermissionsReport | null>>({});
  const [permScopes, setPermScopes] = useState<Record<string, PermissionScope[] | null>>({});
  const [switching, setSwitching] = useState<string | null>(null);
  const [switchNotes, setSwitchNotes] = useState<Record<string, SwitchNote>>({});

  const searchRef = useRef<HTMLInputElement>(null);
  /** Tools whose scope list has been asked for. See `loadPerms`. */
  const scopesAsked = useRef<Set<string>>(new Set());

  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
      setStatuses(await statusAll());
      setError(null);
      setRefreshedAt(Date.now());
    } catch (e) {
      setError(String(e));
    } finally {
      setRefreshing(false);
      setNow(Date.now());
    }
  }, []);

  useEffect(() => {
    void refresh();
    const poll = setInterval(() => void refresh(), POLL_MS);
    const tick = setInterval(() => setNow(Date.now()), TICK_MS);
    return () => {
      clearInterval(poll);
      clearInterval(tick);
    };
  }, [refresh]);

  useEffect(() => {
    getVersion()
      .then(setVersion)
      .catch(() => setVersion(""));
  }, []);

  const detailOpen = detail !== null;

  // `/` jumps to search, Esc clears the filters. Esc belongs to the detail
  // view while one is open, so it only reaches the board when nothing is.
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      const typing = el?.tagName === "INPUT" || el?.tagName === "TEXTAREA";
      if (e.key === "/" && !typing) {
        e.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      } else if (e.key === "Escape" && !detailOpen) {
        setFilters(NO_FILTERS);
        setView("board");
        searchRef.current?.blur();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [detailOpen]);

  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;

  const actions = useMemo(
    () => ({
      verifyRow(tool: string, profileId: string) {
        const key = rowKey(tool, profileId);
        setVerdicts((v) => ({ ...v, [key]: null }));
        verifyProfile(tool, profileId)
          .then((outcome) => setVerdicts((v) => ({ ...v, [key]: outcome })))
          .catch((e) =>
            setVerdicts((v) => ({ ...v, [key]: { result: "invalid", tool, detail: String(e) } })),
          );
      },
      loadPerms(tool: string, scope?: string) {
        setPerms((p) => ({ ...p, [tool]: null }));
        const read = scope === undefined ? fetchPerms(tool) : permissionsIn(tool, scope);
        read
          .then((report) => setPerms((p) => ({ ...p, [tool]: report })))
          .catch((e) =>
            setPerms((p) => ({
              ...p,
              [tool]: {
                tool,
                supported: false,
                subject: null,
                scopes: [],
                notes: [String(e)],
                hint: null,
                scope,
              },
            })),
          );

        // The scope list rides along with the first read, not with the render:
        // it execs the tool's CLI too, and the click that asked for
        // permissions is the consent for both. Once per tool — the guard is a
        // ref rather than the state it fills, because a re-read arrives before
        // the first answer does. A failure parks `[]`, which reads as "no
        // picker" rather than retrying forever.
        if (!scopesAsked.current.has(tool)) {
          scopesAsked.current.add(tool);
          setPermScopes((s) => ({ ...s, [tool]: null }));
          permissionScopes(tool)
            .then((list) => setPermScopes((s) => ({ ...s, [tool]: list })))
            .catch(() => setPermScopes((s) => ({ ...s, [tool]: [] })));
        }
      },
      switchTo(tool: string, profileId: string) {
        setSwitching(rowKey(tool, profileId));
        setSwitchNotes((n) => {
          const next = { ...n };
          delete next[tool];
          return next;
        });
        switchProfile(tool, profileId)
          .then((outcome) => setSwitchNotes((n) => ({ ...n, [tool]: switchMessage(outcome) })))
          .catch((e) => setSwitchNotes((n) => ({ ...n, [tool]: { text: String(e), bad: true } })))
          .finally(() => {
            setSwitching(null);
            void refreshRef.current();
          });
      },
      open(tool: string, opts?: { permissions?: boolean }) {
        setDetail({ tool, permissions: Boolean(opts?.permissions) });
      },
    }),
    [],
  );

  const panel: Panel = { now, verdicts, perms, permScopes, switching, switchNotes, ...actions };

  const all = statuses ?? [];
  const shown = useMemo(() => apply(all, filters), [all, filters]);
  const filtered = isFiltered(filters);

  let summary: string;
  if (view === "keys") {
    summary = "key vault — keys no CLI tracks";
  } else if (view === "mcp") {
    summary = "MCP clients — one board per AI client";
  } else if (!statuses) {
    summary = "reading local state…";
  } else if (!filtered) {
    summary = summaryLine(summarize(all, now));
  } else {
    const parts = [`${shown.length} of ${all.length}`];
    if (filters.category) parts.push(categoryLabel(filters.category));
    if (filters.state) parts.push(STATE_LABEL[filters.state]);
    if (filters.query.trim()) parts.push(`“${filters.query.trim()}”`);
    summary = parts.join(" · ");
  }

  const detailStatus = detail ? all.find((s) => s.tool === detail.tool) : undefined;

  return (
    <div className="shell">
      {/* The window has no title bar of its own (Overlay style), so this strip
          is the title bar: it drags the window and clears the traffic lights. */}
      <header className="header" data-tauri-drag-region>
        <span className="wordmark" data-tauri-drag-region>
          patchbay
        </span>
        <span className="summary" data-tauri-drag-region>
          {summary}
        </span>
        <span className="header-right">
          {refreshedAt && <span className="stamp">{clockTime(refreshedAt)}</span>}
          <button type="button" className="action" onClick={() => void refresh()} disabled={refreshing}>
            {refreshing ? <span className="spinner" /> : null}
            refresh
          </button>
        </span>
      </header>

      <div className="body">
        <Sidebar
          ref={searchRef}
          statuses={all}
          filters={filters}
          onChange={setFilters}
          view={view}
          onView={setView}
        />

        <main className="board">
          {/* Above every view, in the flow: an update is worth saying once,
              and never worth covering the thing the window is for. */}
          <UpdateBanner />

          {view === "keys" && <KeysView />}
          {view === "mcp" && <McpView />}

          {view === "board" && (
            /* Same wrapper the other two views use: one idiom for "a view",
               and `min-width: 0` on it is what keeps a wide child scrolling
               inside its own frame rather than pushing the pane. */
            <div className="view">
              {error && (
                <div className="banner">
                  <span className="glyph">△</span>
                  <span>{error}</span>
                </div>
              )}

              {!statuses && !error && <p className="placeholder">probing…</p>}

              {statuses && all.length === 0 && (
                <p className="placeholder">no probes registered — nothing to show</p>
              )}

              {statuses && all.length > 0 && shown.length === 0 && (
                <div className="empty">
                  <p className="empty-line">no tools match</p>
                  <button type="button" className="action" onClick={() => setFilters(NO_FILTERS)}>
                    clear filters
                  </button>
                </div>
              )}

              {shown.length > 0 && (
                <div className="grid">
                  {shown.map((s) => (
                    <ToolCard key={s.tool} status={s} panel={panel} />
                  ))}
                </div>
              )}
            </div>
          )}
        </main>
      </div>

      <footer className="footer">
        <span>{version ? `v${version}` : "patchbay"}</span>
        <span>MIT · pathorsAI/patchbay</span>
      </footer>

      {detail && detailStatus && (
        <ToolDetail
          status={detailStatus}
          panel={panel}
          query={filters.query}
          wantPermissions={detail.permissions}
          onClose={() => setDetail(null)}
        />
      )}
    </div>
  );
}
