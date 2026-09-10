import path from "node:path";

import type { AuthInfo } from "@modelcontextprotocol/server";

import type { AppConfig, WorkspaceProfile } from "../config/schema.js";

export type Risk = "low" | "medium" | "high" | "critical";

export type PolicyDecision = {
  allowed: boolean;
  reason: string;
  requiredScope: string;
  risk: Risk;
  profile?: WorkspaceProfile;
};

const READ_ONLY_TOOLS = new Set([
  "who_am_i",
  "list_devices",
  "ping",
  "get_capabilities",
  "health",
  "version",
  "list_directory",
  "read_file",
  "read_multiple_files",
  "get_file_info",
  "start_search",
  "search_status",
  "search_results",
  "cancel_search",
  "list_processes",
  "read_process_output",
  "admin_verify_release",
  "admin_upgrade_preflight",
  "admin_upgrade_status",
  "admin_verify_post_restart",
  "get_effective_config",
  "validate_config",
  "simulate_policy",
  "recent_tool_calls",
  "active_sessions",
  "resource_stats",
  "readiness",
  "error_details",
]);

const ALWAYS_AVAILABLE = new Set(["ping", "health", "version", "readiness"]);

export class PolicyEngine {
  constructor(
    private readonly config: AppConfig,
    private readonly state: { killSwitch: () => boolean; emergencyReadOnly: () => boolean },
  ) {}

  decide(
    auth: AuthInfo | undefined,
    tool: string,
    requiredScope: string,
    profileName?: string,
    risk: Risk = "low",
  ): PolicyDecision {
    if (!auth)
      return { allowed: false, reason: "missing authenticated identity", requiredScope, risk };
    if (this.state.killSwitch() && !ALWAYS_AVAILABLE.has(tool)) {
      return { allowed: false, reason: "local kill switch is active", requiredScope, risk };
    }
    if (this.state.emergencyReadOnly() && !READ_ONLY_TOOLS.has(tool)) {
      return { allowed: false, reason: "emergency read-only mode is active", requiredScope, risk };
    }
    if (!auth.scopes.includes(requiredScope) && !auth.scopes.includes("admin")) {
      return { allowed: false, reason: `scope ${requiredScope} is required`, requiredScope, risk };
    }
    const selected = profileName ?? this.config.policy.defaultProfile;
    const profile = this.config.profiles[selected];
    if (!profile)
      return {
        allowed: false,
        reason: `workspace profile ${selected} does not exist`,
        requiredScope,
        risk,
      };
    return {
      allowed: true,
      reason: "explicit scope and workspace profile allow the operation",
      requiredScope,
      risk,
      profile,
    };
  }

  commandAllowed(
    profile: WorkspaceProfile,
    executable: string,
    args: string[],
  ): { allowed: boolean; reason: string } {
    if (args.some((arg) => arg.length > 4096 || arg.includes("\0")))
      return { allowed: false, reason: "invalid argument" };
    const normalized = path.win32.normalize(executable).toLowerCase();
    if (profile.allowShell) {
      return { allowed: true, reason: "trusted-owner shell mode permits direct executable access" };
    }
    const rule = profile.commands.find(
      (item) => path.win32.normalize(item.executable).toLowerCase() === normalized,
    );
    if (!rule) return { allowed: false, reason: "executable is not in the profile allowlist" };
    const patterns = rule.argumentPatterns.map((pattern) => new RegExp(pattern, "u"));
    if (patterns.length > 0 && args.some((arg) => !patterns.some((pattern) => pattern.test(arg)))) {
      return { allowed: false, reason: "one or more arguments are outside the allowlist" };
    }
    return { allowed: true, reason: "executable and arguments match an explicit allowlist rule" };
  }
}
