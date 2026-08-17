/** Mirror of the serde shapes in `patchbay-core::types`. */

export type Meta = Record<string, unknown>;

/**
 * How loudly to say a note. Mirrors `patchbay_core::NoteKind`.
 *
 * Before this existed the panel drew every note behind the same amber warning
 * triangle, so "docker has no active registry, which is normal for docker" and
 * "docker's credential store is unreadable" looked identical and the whole
 * board read as a list of complaints.
 */
export type NoteKind = "info" | "warn" | "problem";

export interface Note {
  kind: NoteKind;
  text: string;
}

/** Notes worth a badge on the collapsed card — everything but `info`. */
export const isAlarming = (n: Note): boolean => n.kind !== "info";

/**
 * When — and whether — a login stops working. Mirrors `patchbay_core::Expiry`.
 *
 * `expires_at: null` used to mean three unrelated things at once: never
 * expires, expires but patchbay cannot see when, and expires but the CLI
 * renews it silently. They are different answers and the panel showed one
 * label for all of them.
 */
export type Expiry =
  | { state: "at"; at: string }
  | { state: "no_expiry" }
  | { state: "unknown"; reason?: string }
  /** The CLI renews this. `access_token_expires` is the short-lived token's
   *  own clock — never a deadline anyone has to meet. */
  | { state: "refreshable"; access_token_expires?: string | null };

export interface Profile {
  id: string;
  label: string;
  /**
   * Derived from `expiry` by core: RFC 3339 for a real deadline, null for all
   * three of the states that are not one. Kept for back-compat; prefer
   * `expiry`, which can tell them apart.
   */
  expires_at: string | null;
  expiry: Expiry;
  meta: Meta;
}

/**
 * Whether "which one is active?" is even a question for this tool. Mirrors
 * `patchbay_core::ActiveConcept`.
 *
 * rclone names its remote on every command, docker holds several registry
 * logins at once — for those an empty active slot is the correct answer, not a
 * missing one, and it must not read as "not connected".
 */
export type ActiveConcept = { kind: "selects" } | { kind: "not_applicable"; reason: string };

/** Mirrors `patchbay_core::AdvisoryKind` — an internally tagged enum. */
export type AdvisoryKind =
  | { kind: "renamed"; [k: string]: unknown }
  | { kind: "removed"; [k: string]: unknown }
  | { kind: "unmaintained"; [k: string]: unknown }
  | { kind: "info" };

/** A curated notice about a tool: a rename, a removal, an end-of-life. */
export interface Advisory {
  tool: string;
  kind: AdvisoryKind;
  message: string;
  url: string | null;
}

/**
 * Mirrors `Advisory::is_blocking` — something removed or abandoned is worth
 * alarming about; a rename you can keep ignoring is not.
 */
export const isBlockingAdvisory = (a: Advisory): boolean =>
  a.kind.kind === "removed" || a.kind.kind === "unmaintained";

/** The categories this build of the panel knows by name. */
export type KnownCategory =
  | "cloud"
  | "code"
  | "secrets"
  | "cluster"
  | "edge"
  | "storage"
  | "containers"
  | "network"
  | "payments"
  | "ai"
  | "other";

/**
 * Mirrors `patchbay_core::ToolCategory` (serde snake_case).
 *
 * The `(string & {})` arm is deliberate and load-bearing. Core owns this
 * vocabulary and grows it; the panel ships separately and will be behind. The
 * failure mode to design out is a *silent* one — core gains a category, the
 * panel drops it from the sidebar and the user sees the new tools on the board
 * with no way to filter to them. So an unknown category stays a legal value,
 * gets a title-cased label from `categoryLabel`, and sorts to the end of the
 * list rather than disappearing from it. Nothing here may be keyed off an
 * exhaustive list of categories.
 */
export type ToolCategory = KnownCategory | (string & {});

/** Mirrors `patchbay_core::ConnectionState`. Derived in core, not here. */
export type ConnectionState = "connected" | "attention" | "disconnected" | "not_installed";

const CATEGORY_LABEL: Record<KnownCategory, string> = {
  cloud: "Cloud",
  code: "Code",
  secrets: "Secrets",
  cluster: "Cluster",
  edge: "Edge",
  storage: "Storage",
  containers: "Containers",
  network: "Network",
  payments: "Payments",
  ai: "AI",
  other: "Other",
};

/**
 * Display name for a category. Known ones are spelled the way we want them
 * (`ai` → "AI"); anything else is title-cased off the wire string, which is
 * plain enough to be useful and honest about being unrecognised.
 */
export function categoryLabel(c: ToolCategory): string {
  return (
    CATEGORY_LABEL[c as KnownCategory] ??
    c
      .split(/[_-]+/)
      .filter(Boolean)
      .map((w) => w[0].toUpperCase() + w.slice(1))
      .join(" ")
  );
}

/**
 * The order the sidebar lists categories in — roughly widest blast radius
 * first. It is an ordering hint, *not* the set of categories: the set comes
 * from the data. Anything not named here sorts after everything that is.
 */
export const CATEGORY_ORDER: KnownCategory[] = [
  "cloud",
  "code",
  "secrets",
  "cluster",
  "edge",
  "storage",
  "containers",
  "network",
  "payments",
  "ai",
  "other",
];

/**
 * Every category actually present in this status set, in `CATEGORY_ORDER`,
 * with unrecognised ones appended alphabetically. Derived from the data on
 * purpose — see the note on `ToolCategory`.
 */
export function categoriesPresent(categories: Iterable<ToolCategory>): ToolCategory[] {
  const rank = (c: ToolCategory) => {
    const i = CATEGORY_ORDER.indexOf(c as KnownCategory);
    return i < 0 ? CATEGORY_ORDER.length : i;
  };
  return [...new Set(categories)].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

/** Listed in the order the sidebar shows them: worst news first. */
export const STATES: ConnectionState[] = ["connected", "attention", "disconnected", "not_installed"];

export const STATE_LABEL: Record<ConnectionState, string> = {
  connected: "Connected",
  attention: "Attention",
  disconnected: "Disconnected",
  not_installed: "Not installed",
};

/** Mirrors `patchbay_core::KeyExpiryState`. Derived in core against its own
 *  30-day "expiring soon" rule, so the vault table and the board agree. */
export type KeyExpiryState = "expired" | "expiring_soon" | "valid" | "no_expiry";

export const KEY_EXPIRY_LABEL: Record<KeyExpiryState, string> = {
  expired: "expired",
  expiring_soon: "expiring soon",
  valid: "valid",
  no_expiry: "no expiry",
};

/** The chip class each vault verdict draws with; shares the board's palette. */
export const KEY_EXPIRY_LEVEL: Record<KeyExpiryState, string> = {
  expired: "expired",
  expiring_soon: "warn",
  valid: "ok",
  no_expiry: "unknown",
};

/**
 * A vault key as it rides along on a tool's status — metadata only. There is no
 * secret value in this shape and there must never be one: the vault's values
 * live in the OS keychain and the panel has no command that can reach them.
 */
export interface KeyRef {
  id: string;
  label: string;
  /** Last 4 characters of the secret — enough to match against a dashboard. */
  last4: string;
  expires_at: string | null;
  expiry_state: KeyExpiryState;
}

export interface ToolStatus {
  tool: string;
  installed: boolean;
  category: ToolCategory;
  profiles: Profile[];
  active: string | null;
  /** Whether an empty `active` is normal for this tool. */
  active_concept: ActiveConcept;
  notes: Note[];
  registered_keys: KeyRef[];
  /**
   * Curated notices — renames, removals, end-of-life. Core has always
   * serialized these and the panel silently dropped them by not declaring the
   * field, so a tool that had been *removed* looked the same as one that had
   * not. Static data, so they are here whether or not the version cache is
   * warm.
   */
  advisories: Advisory[];
  connection_state: ConnectionState;
}

/** A full vault row: `patchbay_core::KeyEntry` plus the panel's derived state. */
export interface KeyRow {
  id: string;
  provider: string;
  label: string;
  purpose: string | null;
  scopes: string[];
  created_at: string;
  expires_at: string | null;
  last4: string;
  /** Who registered it: `"cli"`, `"mcp:<client>"`, `"gui"`. */
  source: string;
  expiry_state: KeyExpiryState;
}

/**
 * The metadata half of a registration, as `key_add` takes it. The secret is
 * deliberately *not* a field here: it is passed separately, so no object in the
 * panel ever carries a value, not even in flight.
 *
 * Blank optional fields are absent fields — the backend trims and drops them.
 * `expires` is `YYYY-MM-DD` or a full timestamp; the backend parses it and
 * refuses anything it cannot read.
 */
export interface NewKeyInput {
  id: string;
  provider: string;
  label: string;
  purpose: string | null;
  scopes: string[];
  expires: string | null;
  endpoint: string | null;
  /** Replace an existing entry under this id — a rotation, not an accident. */
  overwrite: boolean;
}

/** What `key_remove` reports: enough to name what is gone, nothing more. */
export interface RemovedKey {
  id: string;
  last4: string;
}

/** Mirrors `patchbay_core::McpTransport` — an internally tagged enum. */
export type McpTransport =
  | { transport: "stdio"; command: string; args_len: number }
  | { transport: "http"; url: string }
  | { transport: "sse"; url: string };

/** One server as one client has it registered. Names of env vars and headers
 *  only — core never reads their values, which is where the tokens live. */
export type McpServerEntry = McpTransport & {
  name: string;
  /** Claude Code only: `"user"` or `"project:<path>"`. `null` elsewhere. */
  scope: string | null;
  env_keys: string[];
  header_keys: string[];
};

export interface McpClient {
  client: string;
  label: string;
  config_path: string;
  present: boolean;
  servers: McpServerEntry[];
  notes: Note[];
}

/** The three transports, as a spec that is about to be written. */
export type McpTransportKind = "stdio" | "http" | "sse";

/**
 * Mirrors the Tauri shell's `McpTransportWire` — `McpTransport` with the values
 * back in: the arguments themselves rather than a count.
 */
export type McpTransportSpec =
  | { transport: "stdio"; command: string; args: string[] }
  | { transport: "http"; url: string }
  | { transport: "sse"; url: string };

/**
 * One server as one client has it written down, values included.
 *
 * The only shape in the panel that carries MCP secrets — an `Authorization`
 * header, a `--api-key=…` argument, a token in `env`. It arrives from
 * `mcpReadSpec` for one server the user opened, lives in that drawer's form
 * state, and leaves through `mcpAdd`. It must never be put in the list state
 * the matrix renders from, and must never be logged.
 *
 * Pairs, not objects: file order is what an edit has to preserve.
 */
export type McpSpec = McpTransportSpec & {
  env: [string, string][];
  headers: [string, string][];
};

/** Mirrors `patchbay_core::mcp_clients::WriteReport`. */
export interface McpWriteReport {
  client: string;
  label: string;
  name: string;
  config_path: string;
  /** Where the undo lives. Null only when the config file was created. */
  backup_path: string | null;
  created_file: boolean;
  /** Format caveats and the restart hint. Show all of them. */
  notes: Note[];
}

/** Mirrors `patchbay_core::mcp_clients::CopyReport`. */
export interface McpCopyReport {
  name: string;
  from: string;
  summary: string;
  /** Names of env vars whose VALUES travelled. Say so. */
  env_carried: string[];
  /** Names of headers whose VALUES travelled. Same. */
  header_carried: string[];
  written: McpWriteReport[];
}

/**
 * Whether this client has the server in a scope patchbay will write.
 *
 * Mirrors `McpServerEntry::is_writable_scope`. A Claude Code entry under
 * `projects.<path>` is that project's business: core reads it, labels it, and
 * refuses to touch it — so the panel must not offer to.
 */
export const isWritableScope = (e: McpServerEntry): boolean =>
  !(e.scope?.startsWith("project:") ?? false);

export type SwitchOutcome =
  | { result: "switched"; tool: string; profile_id: string; detail: string; notes: string[] }
  | { result: "unsupported"; tool: string; reason: string; hint: string | null }
  /** patchbay itself is running with command execution switched off. A fact
   *  about patchbay's configuration, not about the user's login — so the panel
   *  disables the button and explains in a tooltip rather than filing a note. */
  | { result: "exec_disabled"; tool: string; hint: string | null }
  | { result: "unknown_profile"; tool: string; profile_id: string; available: string[] }
  | { result: "failed"; tool: string; profile_id: string; detail: string };

export type VerifyOutcome =
  | { result: "valid"; tool: string; detail: string }
  | { result: "invalid"; tool: string; detail: string }
  | { result: "unsupported"; tool: string; reason: string; hint: string | null }
  /** See `SwitchOutcome`'s variant of the same name. */
  | { result: "exec_disabled"; tool: string; hint: string | null };

/**
 * One thing a tool's permissions can be read *against*. Some tools grant per
 * resource rather than per credential — a Google account's IAM roles live on a
 * project — so the question needs a scope before it has an answer.
 */
export interface PermissionScope {
  /** What `permissionsIn` takes, e.g. a GCP project id. */
  id: string;
  label: string;
  /** The scope the tool is already configured for; the picker opens on it. */
  active: boolean;
}

export interface PermissionsReport {
  tool: string;
  supported: boolean;
  subject: string | null;
  scopes: string[];
  notes: Note[];
  hint: string | null;
  /** Which scope this report is about. Absent for tools that have none. */
  scope?: string;
}
