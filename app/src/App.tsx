import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { permissions as fetchPerms, statusAll, switchProfile, verify as runVerify } from "./api";
import { clockTime, summarize, summaryLine } from "./expiry";
import { apply, isFiltered, NO_FILTERS, type Filters } from "./filters";
import { switchMessage, type Panel, type SwitchNote } from "./panel";
import { CATEGORY_LABEL, STATE_LABEL, type PermissionsReport, type ToolStatus, type VerifyOutcome } from "./types";
import { Sidebar } from "./components/Sidebar";
import { ToolCard } from "./components/ToolCard";
import { ToolDetail } from "./components/ToolDetail";

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

  const [detail, setDetail] = useState<{ tool: string; permissions: boolean } | null>(null);
  const [verdicts, setVerdicts] = useState<Record<string, VerifyOutcome | null>>({});
  const [perms, setPerms] = useState<Record<string, PermissionsReport | null>>({});
  const [switching, setSwitching] = useState<string | null>(null);
  const [switchNotes, setSwitchNotes] = useState<Record<string, SwitchNote>>({});

  const searchRef = useRef<HTMLInputElement>(null);

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
      verify(tool: string) {
        setVerdicts((v) => ({ ...v, [tool]: null }));
        runVerify(tool)
          .then((outcome) => setVerdicts((v) => ({ ...v, [tool]: outcome })))
          .catch((e) =>
            setVerdicts((v) => ({ ...v, [tool]: { result: "invalid", tool, detail: String(e) } })),
          );
      },
      loadPerms(tool: string) {
        setPerms((p) => ({ ...p, [tool]: null }));
        fetchPerms(tool)
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
              },
            })),
          );
      },
      switchTo(tool: string, profileId: string) {
        setSwitching(`${tool}:${profileId}`);
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

  const panel: Panel = { now, verdicts, perms, switching, switchNotes, ...actions };

  const all = statuses ?? [];
  const shown = useMemo(() => apply(all, filters), [all, filters]);
  const filtered = isFiltered(filters);

  let summary: string;
  if (!statuses) {
    summary = "reading local state…";
  } else if (!filtered) {
    summary = summaryLine(summarize(all, now));
  } else {
    const parts = [`${shown.length} of ${all.length}`];
    if (filters.category) parts.push(CATEGORY_LABEL[filters.category]);
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
          <button className="action" onClick={() => void refresh()} disabled={refreshing}>
            {refreshing ? <span className="spinner" /> : null}
            refresh
          </button>
        </span>
      </header>

      <div className="body">
        <Sidebar ref={searchRef} statuses={all} filters={filters} onChange={setFilters} />

        <main className="board">
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
              <button className="action" onClick={() => setFilters(NO_FILTERS)}>
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
