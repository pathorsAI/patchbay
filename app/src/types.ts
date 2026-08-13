/** Mirror of the serde shapes in `patchbay-core::types`. */

export type Meta = Record<string, unknown>;

export interface Profile {
  id: string;
  label: string;
  /** RFC 3339, or null when the tool does not expose an expiry. */
  expires_at: string | null;
  meta: Meta;
}

/** Mirrors `patchbay_core::ToolCategory` (serde snake_case). */
export type ToolCategory = "cloud" | "code" | "secrets" | "cluster" | "edge" | "storage" | "other";

/** Mirrors `patchbay_core::ConnectionState`. Derived in core, not here. */
export type ConnectionState = "connected" | "attention" | "disconnected" | "not_installed";

export const CATEGORY_LABEL: Record<ToolCategory, string> = {
  cloud: "Cloud",
  code: "Code",
  secrets: "Secrets",
  cluster: "Cluster",
  edge: "Edge",
  storage: "Storage",
  other: "Other",
};

/** Listed in the order the sidebar shows them: worst news first. */
export const STATES: ConnectionState[] = ["connected", "attention", "disconnected", "not_installed"];

export const STATE_LABEL: Record<ConnectionState, string> = {
  connected: "Connected",
  attention: "Attention",
  disconnected: "Disconnected",
  not_installed: "Not installed",
};

export interface ToolStatus {
  tool: string;
  installed: boolean;
  category: ToolCategory;
  profiles: Profile[];
  active: string | null;
  notes: string[];
  connection_state: ConnectionState;
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
