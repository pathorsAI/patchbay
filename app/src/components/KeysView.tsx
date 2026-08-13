import { useEffect, useState } from "react";
import { keysList } from "../api";
import { Copyable } from "./Copyable";
import { KEY_EXPIRY_LABEL, KEY_EXPIRY_LEVEL, type KeyRow } from "../types";

/**
 * The key vault: the standalone API keys no CLI has ever heard of, which the
 * user registered with patchbay on purpose. Read-only in the panel — adding a
 * key means handing over a secret, and that belongs on the command line where
 * the value never crosses a process boundary it did not have to.
 *
 * Metadata only, and there is no code path here that could show otherwise: the
 * `keys_list` command returns `last4` and nothing else derived from the value.
 */
export function KeysView() {
  const [rows, setRows] = useState<KeyRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    keysList()
      .then((r) => live && setRows(r))
      .catch((e) => live && setError(String(e)));
    return () => {
      live = false;
    };
  }, []);

  if (error) {
    return (
      <div className="banner">
        <span className="glyph">△</span>
        <span>{error}</span>
      </div>
    );
  }

  if (!rows) return <p className="placeholder">reading the vault…</p>;

  if (rows.length === 0) {
    return (
      <div className="empty">
        <p className="empty-line">no keys registered</p>
        <p className="muted small vault-blurb">
          The vault holds API keys that no CLI tracks — a Cloudflare token used from a script, a
          provider key an agent was handed. Metadata lives in a JSON file; the value goes straight
          to the OS keychain.
        </p>
        {/* patchbay runs its own actions rather than handing out commands, and
            this is the deliberate exception: registering a key means typing the
            secret somewhere, and the panel is not that somewhere. Nothing here
            ever accepts or displays a value, which is the whole point. */}
        <div className="last-resort">
          <span className="last-resort-why">
            Adding a key has to happen on the command line: it means typing the secret itself, and
            the panel deliberately never takes one.
          </span>
          <Copyable text="pb key add <id> --provider cloudflare --label 'deploy token'" />
        </div>
      </div>
    );
  }

  return (
    <div className="view">
      <div className="view-head">
        <h2 className="view-title">Key vault</h2>
        <span className="view-sub">
          {rows.length} {rows.length === 1 ? "key" : "keys"} · metadata only
        </span>
      </div>

      <div className="scroller">
        <table className="table table-keys">
          <thead>
            <tr>
              <th>id</th>
              <th>provider</th>
              <th>label</th>
              <th>last 4</th>
              <th>expiry</th>
              <th>purpose</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((k) => (
              <tr key={k.id}>
                <td className="cell-id">{k.id}</td>
                <td className="cell-mono">{k.provider}</td>
                <td>{k.label}</td>
                {/* The only thing on this page derived from a secret value. */}
                <td className="cell-mono cell-last4">··{k.last4}</td>
                <td>
                  <span
                    className={`chip chip-${KEY_EXPIRY_LEVEL[k.expiry_state]}`}
                    title={k.expires_at ?? "no expiry recorded"}
                  >
                    {KEY_EXPIRY_LABEL[k.expiry_state]}
                  </span>
                </td>
                <td className="cell-purpose">{k.purpose ?? <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
