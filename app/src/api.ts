import { invoke } from "@tauri-apps/api/core";
import type {
  KeyRow,
  McpClient,
  PermissionsReport,
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

/** Vault metadata. Read-only, and there is no command that returns a value. */
export const keysList = () => invoke<KeyRow[]>("keys_list");

export const mcpList = () => invoke<McpClient[]>("mcp_list");
