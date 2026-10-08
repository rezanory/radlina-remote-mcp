/**
 * Standalone macOS enrollment-readiness guard.
 * This is NOT a device registry, an enrollment authority, or a proof that
 * production multi-device routing has been accepted.
 */
export interface TailscaleMacStatus {
  BackendState?: string;
  CurrentTailnet?: { Name?: string; MagicDNSSuffix?: string };
  MagicDNSSuffix?: string;
  Self?: {
    ID?: string;
    OS?: string;
    HostName?: string;
    DNSName?: string;
    Online?: boolean;
    TailscaleIPs?: string[];
  };
}

export interface MacReadinessRequirements {
  platform: string;
  expectedTailnet: string;
  expectedMagicDnsSuffix: string;
  approvedMacNodeId: string;
  windowsPingSucceeded: boolean;
}

export type MacReadinessCheck = {
  checks: {
    darwinHost: boolean;
    tailscaleRunning: boolean;
    correctTailnet: boolean;
    correctMagicDnsSuffix: boolean;
    actualMacOs: boolean;
    macOnline: boolean;
    approvedNodeIdPresent: boolean;
    nodeIdMatchesApproval: boolean;
    macDnsInTailnet: boolean;
    windowsReachable: boolean;
  };
  ready: boolean;
  failedChecks: string[];
};

export function assessMacReadiness(
  status: TailscaleMacStatus,
  requirement: MacReadinessRequirements,
): MacReadinessCheck {
  const suffix = (status.MagicDNSSuffix ?? status.CurrentTailnet?.MagicDNSSuffix ?? "")
    .replace(/\.$/u, "")
    .toLowerCase();
  const requiredSuffix = requirement.expectedMagicDnsSuffix.replace(/\.$/u, "").toLowerCase();
  const macDns = (status.Self?.DNSName ?? "").replace(/\.$/u, "").toLowerCase();
  const pinnedId = requirement.approvedMacNodeId.trim();
  const checks = {
    darwinHost: requirement.platform === "darwin",
    tailscaleRunning: status.BackendState === "Running",
    correctTailnet: status.CurrentTailnet?.Name === requirement.expectedTailnet,
    correctMagicDnsSuffix: Boolean(requiredSuffix) && suffix === requiredSuffix,
    actualMacOs: status.Self?.OS?.toLowerCase() === "macos",
    macOnline: status.Self?.Online === true,
    approvedNodeIdPresent: pinnedId.length > 0,
    nodeIdMatchesApproval: pinnedId.length > 0 && status.Self?.ID === pinnedId,
    macDnsInTailnet: Boolean(macDns) && macDns.endsWith(`.${requiredSuffix}`),
    windowsReachable: requirement.windowsPingSucceeded,
  };
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name);
  return { checks, ready: failedChecks.length === 0, failedChecks };
}
