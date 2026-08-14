import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

/**
 * In-app self-update.
 *
 * The updater asks the signed release feed named in `tauri.conf.json`
 * (`plugins.updater`) whether a newer build exists, and only ever *offers* it:
 * downloading, installing and relaunching all happen behind a click. patchbay
 * is a thing you open to answer a question about your logins, so an update
 * must never be the thing that happens instead.
 *
 * `check` and `relaunch` are imported STATICALLY on purpose. A dynamic import
 * of `relaunch` after `downloadAndInstall` would go looking for its JS chunk in
 * the bundle the install has just replaced on disk; the import rejects and the
 * app never restarts. Loading both at startup never touches the swapped bundle.
 */

/** What the banner needs to say. */
export interface AvailableUpdate {
  version: string;
  /** The release notes for that version, or "" when the feed carried none. */
  notes: string;
}

/**
 * The live handle. It carries `downloadAndInstall`, so it cannot travel through
 * React state — the banner holds the version string, this module holds the
 * thing that can act on it.
 */
let pending: Update | null = null;

/**
 * Ask the feed. `null` for "nothing newer", and also for every failure: an
 * offline machine, a rate-limited endpoint or a release without updater
 * artifacts are all "no update to offer today", none of which is a problem the
 * user opened this window to hear about.
 */
export async function checkForUpdate(): Promise<AvailableUpdate | null> {
  // Dev has no updater artifacts and no signature to verify against, so the
  // check can only ever fail — and a banner would be in the way regardless.
  if (import.meta.env.DEV) return null;
  try {
    const update = await check();
    if (!update) return null;
    pending = update;
    return { version: update.version, notes: update.body ?? "" };
  } catch (e) {
    console.warn("patchbay: update check failed", e);
    return null;
  }
}

/**
 * Download, verify, install, relaunch. `onProgress` gets a percentage while the
 * bytes come down, or `null` when the feed did not declare a content length —
 * the caller shows "updating…" rather than a number it made up.
 *
 * Only returns on failure: a successful relaunch replaces this process.
 */
export async function installUpdate(onProgress: (pct: number | null) => void): Promise<void> {
  if (!pending) throw new Error("no update is pending");
  let total = 0;
  let got = 0;
  await pending.downloadAndInstall((e) => {
    if (e.event === "Started") {
      total = e.data.contentLength ?? 0;
      onProgress(total > 0 ? 0 : null);
    } else if (e.event === "Progress") {
      got += e.data.chunkLength;
      onProgress(total > 0 ? Math.min(100, Math.round((got / total) * 100)) : null);
    }
  });
  await relaunch();
}
