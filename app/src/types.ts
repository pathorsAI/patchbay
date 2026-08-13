/** Mirror of the serde shapes in `patchbay-core::types`. */

export type Meta = Record<string, unknown>;

export interface Profile {
  id: string;
  label: string;
  /** RFC 3339, or null when the tool does not expose an expiry. */
  expires_at: string | null;
  meta: Meta;
}

export interface ToolStatus {
  tool: string;
  installed: boolean;
  profiles: Profile[];
  active: string | null;
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
