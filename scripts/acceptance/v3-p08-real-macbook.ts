import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promisify } from "node:util";

import {
  assessMacReadiness,
  type TailscaleMacStatus,
} from "../enrollment/macbook-readiness-policy.js";

const execFile = promisify(execFileCallback);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

async function run(executable: string, args: string[], cwd = root) {
  return await execFile(executable, args, {
    cwd,
    timeout: 120_000,
    maxBuffer: 4 * 1024 * 1024,
  });
}

async function tailscaleCli(): Promise<string> {
  for (const candidate of ["tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"]) {
    try {
      await run(candidate, ["version"]);
      return candidate;
    } catch {
      // Only known macOS Tailscale binaries are considered.
    }
  }
  throw new Error("Tailscale CLI is unavailable on the MacBook");
}

type LocalRuntimeOutput = {
  acceptance?: string;
  execution?: Record<string, unknown>;
  output?: Record<string, unknown>;
};

async function runMain(): Promise<void> {
  if (process.platform !== "darwin") {
    process.stdout.write(
      JSON.stringify({
        readiness: "BLOCKED",
        reason: "REAL_MACBOOK_REQUIRED",
        platform: process.platform,
        productionAcceptance: "NOT_GRANTED",
      }) + "\n",
    );
    process.exitCode = 2;
    return;
  }

  const expectedTailnet = process.env["RADLINA_EXPECTED_TAILNET"] ?? "rezanory.github";
  const expectedMagicDnsSuffix = process.env["RADLINA_EXPECTED_MAGICDNS"] ?? "taile17c9e.ts.net";
  const windowsDns =
    process.env["RADLINA_WINDOWS_TAILSCALE_DNS"] ?? "laptop-13qineif.taile17c9e.ts.net";
  // Must be set by the owner after inspecting the actual MacBook's Tailscale node ID.
  // A logical label such as macbook-main is never sufficient.
  const approvedMacNodeId = process.env["RADLINA_APPROVED_MAC_TAILSCALE_NODE_ID"] ?? "";

  const cli = await tailscaleCli();
  const raw = await run(cli, ["status", "--json"]);
  const status = JSON.parse(raw.stdout) as TailscaleMacStatus;

  let windowsPingSucceeded = false;
  let pingReason = "";
  try {
    const response = await run(cli, ["ping", "--c", "3", windowsDns]);
    windowsPingSucceeded = /\bpong\b/iu.test(response.stdout);
    pingReason = windowsPingSucceeded ? "verified pong" : "missing pong evidence";
  } catch (error) {
    pingReason = error instanceof Error ? error.message : "ping failed";
  }

  const guard = assessMacReadiness(status, {
    platform: process.platform,
    expectedTailnet,
    expectedMagicDnsSuffix,
    approvedMacNodeId,
    windowsPingSucceeded,
  });

  const gitHead = (await run("git", ["rev-parse", "HEAD"])).stdout.trim();
  const gitTree = (await run("git", ["rev-parse", "HEAD^{tree}"])).stdout.trim();

  const evidenceBase = {
    schemaVersion: "radlina.v3.macbook-readiness/v1",
    source: { commit: gitHead, tree: gitTree },
    device: {
      logicalDeviceId: "macbook-main",
      hostname: status.Self?.HostName ?? null,
      tailscaleNodeId: status.Self?.ID ?? null,
      tailscaleDnsName: status.Self?.DNSName ?? null,
      platform: "macos",
    },
    network: {
      backend: status.BackendState ?? null,
      tailnet: status.CurrentTailnet?.Name ?? null,
      magicDnsSuffix: status.MagicDNSSuffix ?? status.CurrentTailnet?.MagicDNSSuffix ?? null,
      windowsDns,
      pingReason,
    },
    guard,
  };

  if (!guard.ready) {
    process.stdout.write(
      JSON.stringify({
        ...evidenceBase,
        readiness: "BLOCKED",
        productionAcceptance: "NOT_GRANTED",
        reason: "MACBOOK_IDENTITY_OR_NETWORK_PREFLIGHT_FAILED",
      }) + "\n",
    );
    process.exitCode = 2;
    return;
  }

  // Exercise a REAL ripgrep process on the verified Mac, not a fake SearchPort.
  const scratch = await mkdtemp(path.join(tmpdir(), "radlina-macbook-rg-"));
  let ripgrepExecuted = false;
  try {
    const markerFile = path.join(scratch, "radlina-p08-search-evidence.txt");
    await writeFile(markerFile, "radlina-p08-search-evidence");
    const rg = await run("rg", ["-l", "-F", "radlina-p08-search-evidence", scratch]);
    ripgrepExecuted = rg.stdout.includes("radlina-p08-search-evidence.txt");
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }

  const tsxCli = path.join(root, "node_modules", "tsx", "dist", "cli.mjs");
  const localScript = path.join(root, "scripts", "acceptance", "v3-p08-macos-agent.ts");
  const local = await run(process.execPath, [tsxCli, localScript]);
  const lines = local.stdout.trim().split(/\r?\n/u).filter(Boolean);
  const localEvidence = JSON.parse(lines.at(-1) ?? "{}") as LocalRuntimeOutput;
  const localRuntimePassed = localEvidence.acceptance === "PASS";
  const readiness = ripgrepExecuted && localRuntimePassed ? "PASS" : "FAIL";

  process.stdout.write(
    JSON.stringify({
      ...evidenceBase,
      localMacRuntime: {
        macosAgentRuntime: localEvidence.acceptance ?? "MISSING",
        execution: localEvidence.execution ?? null,
        output: localEvidence.output ?? null,
        realRipgrepExecuted: ripgrepExecuted,
        note: "The MacOSDeviceAgent runner uses a test fixture for trusted identity. It is NOT a live V3 registry enrollment.",
      },
      readiness,
      productionAcceptance: "PENDING_TRUSTED_DEVICE_REGISTRY_AND_LIVE_ROUTE_ACCEPTANCE",
      officialAcceptedCountMustNotIncrease: true,
    }) + "\n",
  );
  if (readiness !== "PASS") process.exitCode = 1;
}

try {
  await runMain();
} catch (error) {
  process.stdout.write(
    JSON.stringify({
      readiness: "ERROR",
      productionAcceptance: "NOT_GRANTED",
      error: error instanceof Error ? error.message : "unknown MacBook readiness error",
    }) + "\n",
  );
  process.exitCode = 1;
}
