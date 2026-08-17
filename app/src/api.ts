import { invoke } from "@tauri-apps/api/core";
import type {
  KeyRow,
  McpClient,
  McpCopyReport,
  McpSpec,
  McpWriteReport,
  NewKeyInput,
  PermissionsReport,
  RemovedKey,
  SwitchOutcome,
  ToolStatus,
  VerifyOutcome,
} from "./types";

export const statusAll = () => invoke<ToolStatus[]>("status_all");

export const switchProfile = (tool: string, profileId: string) =>
  invoke<SwitchOutcome>("switch_profile", { tool, profileId });

export const verify = (tool: string) => invoke<VerifyOutcome>("verify", { tool });

/**
 * Verify one profile. The panel always asks this way — "is this login still
 * good?" is a question about a credential, not about a tool, and the answer is
 * about the profile named here rather than whichever one happens to be active.
 */
export const verifyProfile = (tool: string, profile: string) =>
  invoke<VerifyOutcome>("verify_profile", { tool, profile });

export const permissions = (tool: string) => invoke<PermissionsReport>("permissions", { tool });

/** Vault metadata. There is no command that returns a value — see `keyAdd`. */
export const keysList = () => invoke<KeyRow[]>("keys_list");

/**
 * Register a key. The secret is a separate argument on purpose: it belongs to
 * no object, is never held in state alongside the metadata, and exists only
 * between the form field and this call. The backend hands it to the same
 * `KeyRegistry::add` the CLI uses and drops it.
 *
 * Values only ever travel in this direction. Nothing in the panel reads one
 * back — `pb key copy <id>` remains the only way out of the vault.
 */
export const keyAdd = (key: NewKeyInput, secret: string) =>
  invoke<KeyRow>("key_add", { ...key, secret });

/** Unregister a key: metadata row and keychain item both. Not a revocation. */
export const keyRemove = (id: string) => invoke<RemovedKey>("key_remove", { id });

/**
 * The matrix. Value-free by construction: env var and header *names*, and a
 * count of a stdio command's arguments. Nothing that comes back from here is a
 * secret, which is why it can be held in view state and refreshed on a timer.
 */
export const mcpList = () => invoke<McpClient[]>("mcp_list");

/**
 * One server's full definition from one client's config, values included.
 *
 * The single read path in the panel that returns MCP secrets, and it is scoped
 * to the one server whose drawer the user opened. Its answer belongs to that
 * drawer's form state and nowhere else — never in the list state the matrix
 * renders from, never in a log line.
 */
export const mcpReadSpec = (client: string, name: string) =>
  invoke<McpSpec>("mcp_read_spec", { client, name });

/**
 * Write a server into one client's config. `overwrite` is the difference
 * between adding and editing: core refuses a name that already exists without
 * it, and an edit is a read-modify-write of the entry that is already there.
 */
export const mcpAdd = (client: string, name: string, spec: McpSpec, overwrite: boolean) =>
  invoke<McpWriteReport>("mcp_add", { client, name, spec, overwrite });

/** Unregister a server from one client. Not a deletion of the server itself. */
export const mcpRemove = (client: string, name: string) =>
  invoke<McpWriteReport>("mcp_remove", { client, name });

/** Copy a server into other clients, translating JSON ↔ TOML on the way. */
export const mcpCopy = (name: string, from: string, to: string[], overwrite: boolean) =>
  invoke<McpCopyReport>("mcp_copy", { name, from, to, overwrite });
