import { Fragment, useCallback, useEffect, useState, type FormEvent } from "react";
import { keyAdd, keyRemove, keysList } from "../api";
import { Copyable } from "./Copyable";
import { TrashGlyph } from "./Glyphs";
import { KEY_EXPIRY_LABEL, KEY_EXPIRY_LEVEL, type KeyRow } from "../types";

/**
 * The key vault: the standalone API keys no CLI has ever heard of, which the
 * user registered with patchbay on purpose.
 *
 * The panel registers and removes them, and does neither of those things with a
 * value it can show you. A secret enters through one masked field, rides one
 * `invoke` call, and lands in the OS keychain; nothing here stores it, echoes
 * it, or can ask for it back. `pb key copy <id>` is still the only way a value
 * leaves the vault — the asymmetry the CLI was built around survives intact.
 *
 * The old rule was "adding happens on the command line", and its reason was
 * argv: a secret passed as an argument is visible in `ps` and written verbatim
 * into shell history. Neither is true of a password field in a native window,
 * so the rule was protecting nothing here and cost the panel the one action a
 * key vault is for.
 */
export function KeysView() {
  const [rows, setRows] = useState<KeyRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  /** The row whose delete is armed. One at a time, and never pre-armed. */
  const [confirming, setConfirming] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  /** The outcome of the last write, in the panel's usual note voice. */
  const [note, setNote] = useState<{ text: string; bad: boolean } | null>(null);

  const load = useCallback(async () => {
    try {
      setRows(await keysList());
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const remove = async (id: string) => {
    setRemoving(id);
    setNote(null);
    try {
      const gone = await keyRemove(id);
      setNote({
        text: `removed ${gone.id} (··${gone.last4}) — patchbay has forgotten it; the credential itself keeps working until you revoke it at the provider`,
        bad: false,
      });
      setConfirming(null);
      await load();
    } catch (e) {
      // Core's errors say what half-state the vault is in; do not paraphrase.
      setNote({ text: String(e), bad: true });
    } finally {
      setRemoving(null);
    }
  };

  const added = async (row: KeyRow) => {
    setAdding(false);
    setNote({ text: `registered ${row.id} (··${row.last4}) — value in the OS keychain`, bad: false });
    await load();
  };

  if (error && !rows) {
    return (
      <div className="banner">
        <span className="glyph">△</span>
        <span>{error}</span>
      </div>
    );
  }

  if (!rows) return <p className="placeholder">reading the vault…</p>;

  return (
    <div className="view">
      <div className="view-head">
        <h2 className="view-title">Key vault</h2>
        <span className="view-sub">
          {rows.length} {rows.length === 1 ? "key" : "keys"} · metadata only
        </span>
        <button className="action" onClick={() => setAdding(true)}>
          add key
        </button>
      </div>

      {error && (
        <div className="banner">
          <span className="glyph">△</span>
          <span>{error}</span>
        </div>
      )}

      {note && (
        <div className={`switch-note${note.bad ? " bad" : ""}`}>
          <span>{note.text}</span>
        </div>
      )}

      {rows.length === 0 ? (
        <div className="empty">
          <p className="empty-line">no keys registered</p>
          <p className="muted small vault-blurb">
            The vault holds API keys that no CLI tracks — a Cloudflare token used from a script, a
            provider key an agent was handed. Metadata lives in a JSON file; the value goes straight
            to the OS keychain, and nothing in this window can read it back.
          </p>
          <button className="action" onClick={() => setAdding(true)}>
            add key
          </button>
          <p className="muted small vault-blurb">
            Already in a terminal? The same registration, with the secret on stdin so it never
            reaches argv or your shell history:
          </p>
          <Copyable text="pbpaste | pb key add <id> --provider cloudflare --label 'deploy token'" />
        </div>
      ) : (
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
                <th aria-label="actions" />
              </tr>
            </thead>
            <tbody>
              {rows.map((k) => (
                <Fragment key={k.id}>
                  <tr>
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
                    <td className="cell-actions">
                      <button
                        className="row-action"
                        onClick={() => setConfirming(confirming === k.id ? null : k.id)}
                        disabled={removing !== null}
                        aria-label={`remove ${k.id}`}
                        title="remove from the vault"
                      >
                        <TrashGlyph />
                      </button>
                    </td>
                  </tr>
                  {confirming === k.id && (
                    <tr className="confirm-row">
                      <td colSpan={7}>
                        <div className="confirm">
                          <span className="confirm-why">
                            Remove <b>{k.id}</b>? This removes the entry and its keychain value; the
                            credential itself keeps working — revoke it at the provider.
                          </span>
                          <button
                            className="row-action"
                            onClick={() => setConfirming(null)}
                            disabled={removing === k.id}
                          >
                            cancel
                          </button>
                          <button
                            className="row-danger"
                            onClick={() => void remove(k.id)}
                            disabled={removing === k.id}
                          >
                            {removing === k.id ? <span className="spinner" /> : null}
                            {removing === k.id ? "removing…" : "remove"}
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {adding && <AddKeyForm onClose={() => setAdding(false)} onAdded={added} />}
    </div>
  );
}

/**
 * The one place in patchbay's UI that takes a secret.
 *
 * It lives in component state for as long as the drawer is open and is cleared
 * on every submit; closing the drawer unmounts the component and takes it with
 * it. It is never logged, never put in the success note, and never written
 * anywhere but the `key_add` payload.
 *
 * Validation is core's job — the registry's messages about slugs, duplicate ids
 * and empty secrets are written to be read, so they are shown verbatim rather
 * than pre-empted. The only client-side rules are the two that decide whether
 * pressing the button could possibly work.
 */
function AddKeyForm({
  onClose,
  onAdded,
}: {
  onClose: () => void;
  onAdded: (row: KeyRow) => void | Promise<void>;
}) {
  const [id, setId] = useState("");
  const [provider, setProvider] = useState("");
  const [label, setLabel] = useState("");
  const [secret, setSecret] = useState("");
  const [more, setMore] = useState(false);
  const [purpose, setPurpose] = useState("");
  const [scopes, setScopes] = useState("");
  const [expires, setExpires] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [overwrite, setOverwrite] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const ready = id.trim().length > 0 && secret.length > 0 && !busy;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    // Taken out of state before the await, so the value the request carries is
    // a local that dies with this function whatever the backend answers.
    const value = secret;
    setSecret("");
    try {
      const row = await keyAdd(
        {
          id: id.trim(),
          provider: provider.trim(),
          label: label.trim(),
          purpose: purpose.trim() || null,
          scopes: scopes
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          expires: expires.trim() || null,
          endpoint: endpoint.trim() || null,
          overwrite,
        },
        value,
      );
      await onAdded(row);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="detail" role="dialog" aria-label="add a key to the vault">
        <header className="detail-head">
          <div className="detail-title">
            <h2 className="tool">add key</h2>
            <span className="detail-sub">metadata to keys.json · value to the OS keychain</span>
          </div>
          <button className="action" onClick={onClose} aria-label="close">
            close
          </button>
        </header>

        <form className="detail-form" onSubmit={(e) => void submit(e)}>
          <label className="field">
            <span className="field-key">id</span>
            <input
              className="field-input"
              value={id}
              onChange={(e) => setId(e.target.value)}
              placeholder="cf-gh-actions-deploy"
              autoFocus
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
            />
            <span className="muted small">
              lowercase slug — letters, digits, <code>-</code> <code>_</code> <code>.</code>
            </span>
          </label>

          <label className="field">
            <span className="field-key">provider</span>
            <input
              className="field-input"
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              placeholder="cloudflare"
              spellCheck={false}
              autoCapitalize="off"
            />
            <span className="muted small">
              free-form; the known ones (cloudflare, github, gcp, aws, azure, infisical) put the key
              beside that tool on the board
            </span>
          </label>

          <label className="field">
            <span className="field-key">label</span>
            <input
              className="field-input"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="CF deploy token"
            />
            <span className="muted small">defaults to the id</span>
          </label>

          <label className="field">
            <span className="field-key">secret</span>
            <input
              className="field-input"
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder="paste the value"
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              autoComplete="off"
            />
            <span className="muted small">
              goes straight to the keychain. The panel keeps only the last 4 characters, and has no
              way to show you this again — <code>pb key copy {id.trim() || "<id>"}</code> is how you
              get it back.
            </span>
          </label>

          <div className="field">
            <button
              type="button"
              className="action"
              onClick={() => setMore(!more)}
              aria-expanded={more}
            >
              {more ? "− " : "+ "}
              optional
            </button>
          </div>

          {more && (
            <>
              <label className="field">
                <span className="field-key">purpose</span>
                <input
                  className="field-input"
                  value={purpose}
                  onChange={(e) => setPurpose(e.target.value)}
                  placeholder="deploy worker from GitHub Actions in pathorsAI/patchbay"
                />
              </label>

              <label className="field">
                <span className="field-key">scopes</span>
                <input
                  className="field-input"
                  value={scopes}
                  onChange={(e) => setScopes(e.target.value)}
                  placeholder="workers:edit, zone:read"
                  spellCheck={false}
                />
                <span className="muted small">comma separated, as the issuer names them</span>
              </label>

              <label className="field">
                <span className="field-key">expires</span>
                <input
                  className="field-input"
                  type="date"
                  value={expires}
                  onChange={(e) => setExpires(e.target.value)}
                />
                <span className="muted small">
                  what lets patchbay warn you before it dies, on the board and in the vault
                </span>
              </label>

              <label className="field">
                <span className="field-key">endpoint</span>
                <input
                  className="field-input"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  placeholder="https://you.grafana.net"
                  spellCheck={false}
                  autoCapitalize="off"
                />
                <span className="muted small">
                  instance root, for providers with more than one address — verification needs it
                </span>
              </label>

              <label className="check">
                <input
                  type="checkbox"
                  checked={overwrite}
                  onChange={(e) => setOverwrite(e.target.checked)}
                />
                <span>
                  rotating — replace the key already registered under this id
                  <span className="muted"> (its registration date becomes today)</span>
                </span>
              </label>
            </>
          )}

          {/* Core's own sentence, unedited: it names the id, says what it
              refused and what to do instead. */}
          {error && (
            <div className="field">
              <div className="banner">
                <span className="glyph">△</span>
                <span>{error}</span>
              </div>
              <span className="muted small">
                the secret field was cleared — paste it again to retry
              </span>
            </div>
          )}

          <div className="section-row">
            <button className="action" type="submit" disabled={!ready}>
              {busy ? <span className="spinner" /> : null}
              {busy ? "registering…" : "register"}
            </button>
            <button className="action" type="button" onClick={onClose} disabled={busy}>
              cancel
            </button>
          </div>
        </form>
      </aside>
    </>
  );
}
