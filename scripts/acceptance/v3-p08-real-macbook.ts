import { execFile as execFileCallback } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

type TailStatus = {
  BackendState?: string;
  CurrentTailnet?: { Name?: string };
  Self?: {
    HostName?: string;
    OS?: string;
    Online?: boolean;
    DNSName?: string;
    TailscaleIPs?: string[];
  };
};

async function run(
  executable: string,
  args: string[],
  options: { cwd?: string } = {},
): Promise<{ stdout: string; stderr: string }> {
  return await execFile(executable, args, {
    cwd: options.cwd,
    timeout: 120_000,
    maxBuffer: 4 * 1024 * 1024,
  });
}

async function resolveTailscale(): Promise<string> {
  const candidates = ["tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"];
  for (const candidate of candidates) {
    try {
      await run(candidate, ["version"]);
      return candidate;
    } catch {
      // Try the next known macOS Tailscale CLI path.
    }
  }
  throw new Error("Tailscale CLI is not available on the MacBook");
}

if (process.platform !== "darwin") {
  process.stdout.write(
    JSON.stringify({
      acceptance: "BLOCKED_REAL_MACBOOK_REQUIRED",
      platform: process.platform,
    }),
  );
  process.exit(2);
}

const expectedTailnet = process.env["RADLINA_EXPECTED_TAILNET"] ?? "rezanory.github";
const windowsDns =
  process.env["RADLINA_WINDOWS_TAILSCALE_DNS"] ?? "laptop-13qineif.taile17c9e.ts.net";

const tailscale = await resolveTailscale();
const statusRaw = await run(tailscale, ["status", "--json"]);
const status = JSON.parse(statusRaw.stdout) as TailStatus;

const tailnetMatches = status.CurrentTailnet?.Name === expectedTailnet;
const selfOnline = status.BackendState === "Running" && status.Self?.Online === true;
const macIdentity =
  typeof status.Self?.OS === "string" && status.Self.OS.toLowerCase().includes("mac");

let windowsReachable = false;
let pingOutput = "";
try {
  const ping = await run(tailscale, ["ping", "--c", "3", windowsDns]);
  pingOutput = ping.stdout.trim();
  windowsReachable = /pong|via/i.test(ping.stdout);
} catch (error) {
  pingOutput = error instanceof Error ? error.message : "tailscale ping failed";
}

const git = await run("git", ["rev-parse", "HEAD"], { cwd: projectRoot });
const sourceCommit = git.stdout.trim();

const tsxCli = path.join(projectRoot, "node_modules", "tsx", "dist", "cli.mjs");
const innerScript = path.join(projectRoot, "scripts", "acceptance", "v3-p08-macos-agent.ts");
const inner = await run(process.execPath, [tsxCli, innerScript], { cwd: projectRoot });

const innerLines = inner.stdout.trim().split(/\r?\n/u).filter(Boolean);
const innerJson = JSON.parse(innerLines.at(-1) ?? "{}") as {
  acceptance?: string;
  execution?: Record<string, unknown>;
  output?: Record<string, unknown>;
};

const runtimeAccepted = innerJson.acceptance === "PASS";
const acceptance =
  tailnetMatches && selfOnline && macIdentity && windowsReachable && runtimeAccepted;

process.stdout.write(
  JSON.stringify({
    input: {
      expectedTailnet,
      windowsDns,
      sourceCommit,
    },
    runtime: {
      tailscale,
      backendState: status.BackendState ?? null,
      tailnet: status.CurrentTailnet?.Name ?? null,
      macHostName: status.Self?.HostName ?? null,
      macDnsName: status.Self?.DNSName ?? null,
      macTailscaleIps: status.Self?.TailscaleIPs ?? [],
    },
    execution: {
      tailnetMatches,
      selfOnline,
      macIdentity,
      windowsReachable,
      pingOutput,
      p08RuntimeAcceptance: innerJson.acceptance ?? null,
      p08Execution: innerJson.execution ?? null,
    },
    output: {
      p08Output: innerJson.output ?? null,
    },
    acceptance: acceptance ? "PASS" : "FAIL",
  }),
);

if (!acceptance) process.exitCode = 1;
