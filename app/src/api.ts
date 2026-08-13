import { invoke } from "@tauri-apps/api/core";
import type {
  KeyRow,
  McpClient,
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
 * good?" is a question about a credential, not about a tool. Core's per-profile
 * verify is still landing, so today the command answers about the active
 * profile; the profile id is already on the wire for when it does.
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

export const mcpList = () => invoke<McpClient[]>("mcp_list");
