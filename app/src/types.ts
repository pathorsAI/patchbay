/** Mirror of the serde shapes in `patchbay-core::types`. */

export type Meta = Record<string, unknown>;

export interface Profile {
  id: string;
  label: string;
  /** RFC 3339, or null when the tool does not expose an expiry. */
  expires_at: string | null;
  meta: Meta;
}

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
  notes: string[];
  registered_keys: KeyRef[];
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
  notes: string[];
}

export type SwitchOutcome =
  | { result: "switched"; tool: string; profile_id: string; detail: string; notes: string[] }
  | { result: "unsupported"; tool: string; reason: string; hint: string | null }
  | { result: "unknown_profile"; tool: string; profile_id: string; available: string[] }
  | { result: "failed"; tool: string; profile_id: string; detail: string };

export type VerifyOutcome =
  | { result: "valid"; tool: string; detail: string }
  | { result: "invalid"; tool: string; detail: string }
  | { result: "unsupported"; tool: string; reason: string; hint: string | null };

export interface PermissionsReport {
  tool: string;
  supported: boolean;
  subject: string | null;
  scopes: string[];
  notes: string[];
  hint: string | null;
}

/**
 * Tools whose `permissions()` can actually answer. Everything else returns
 * `supported: false`, so the panel omits the action rather than offering a
 * button that only ever says "not implemented".
 */
export const PERMISSIONS_TOOLS = new Set(["gh", "wrangler"]);
