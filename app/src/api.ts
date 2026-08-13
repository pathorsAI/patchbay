import { invoke } from "@tauri-apps/api/core";
import type { PermissionsReport, SwitchOutcome, ToolStatus, VerifyOutcome } from "./types";

export const statusAll = () => invoke<ToolStatus[]>("status_all");

export const switchProfile = (tool: string, profileId: string) =>
  invoke<SwitchOutcome>("switch_profile", { tool, profileId });

export const verify = (tool: string) => invoke<VerifyOutcome>("verify", { tool });

export const permissions = (tool: string) => invoke<PermissionsReport>("permissions", { tool });
