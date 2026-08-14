import { useEffect, useState } from "react";
import { checkForUpdate, installUpdate, type AvailableUpdate } from "../lib/update";

/**
 * The one row that says a newer patchbay exists.
 *
 * It sits in the flow above whatever view is open rather than over it: the
 * board is what the window is for, and an update is never urgent enough to
 * cover a login you came here to read. "not now" dismisses it for this session
 * only — nothing is written down, so the next launch asks again, which is the
 * honest behaviour for something the user has neither accepted nor refused.
 */
export function UpdateBanner() {
  const [update, setUpdate] = useState<AvailableUpdate | null>(null);
  const [dismissed, setDismissed] = useState(false);
  /** Percent while downloading, `null` for "working, no number to show". */
  const [progress, setProgress] = useState<number | null | undefined>(undefined);
  const [failure, setFailure] = useState<string | null>(null);

  // One check, shortly after launch. `checkForUpdate` is silent about failure
  // and about dev builds, so there is nothing to guard here.
  useEffect(() => {
    const timer = setTimeout(() => {
      void checkForUpdate().then(setUpdate);
    }, 2000);
    return () => clearTimeout(timer);
  }, []);

  if (!update || dismissed) return null;

  const installing = progress !== undefined;

  const run = () => {
    setFailure(null);
    setProgress(null);
    // installUpdate only ever returns by failing: a relaunch replaces us.
    installUpdate(setProgress).catch((e) => {
      // The install may well have succeeded and only the relaunch failed (an
      // app still under Gatekeeper's translocation cannot restart itself), in
      // which case the new version is already staged. Say so instead of
      // reporting a failure the user cannot act on.
      setProgress(undefined);
      setFailure(`${String(e)} — quit and reopen patchbay to finish the update`);
    });
  };

  return (
    <div className="banner banner-update">
      <span className="glyph">↑</span>
      <span className="banner-text">
        {failure ?? (installing ? updatingLabel(progress) : `patchbay ${update.version} is available`)}
      </span>
      <span className="banner-actions">
        <button className="action" onClick={run} disabled={installing}>
          {installing ? <span className="spinner" /> : null}
          update and relaunch
        </button>
        <button className="action" onClick={() => setDismissed(true)} disabled={installing}>
          not now
        </button>
      </span>
    </div>
  );
}

function updatingLabel(progress: number | null | undefined): string {
  return typeof progress === "number" ? `downloading… ${progress}%` : "downloading…";
}
