import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, renameSync, rmdirSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export type WatchdogCheck = { ok: boolean; detail: string };
export type WatchdogChecks = {
  macOSAgent: WatchdogCheck;
  signedHeartbeat: WatchdogCheck;
  githubRunner: WatchdogCheck;
  gitCommit: WatchdogCheck;
  lastTest: WatchdogCheck;
  tailscale: WatchdogCheck;
};

export type WatchdogState = {
  schema: "radlina.v3.macos-watchdog/v1";
  checkedAt: string;
  deviceId: "macbook-main";
  activeStage: "P08";
  latestCommit: string | null;
  latestSuccessfulTest: string | null;
  latestError: string | null;
  connectionStatus: "CONNECTED" | "DEGRADED";
  status: "HEALTHY" | "DEGRADED" | "BLOCKED";
  consecutiveFailures: number;
  officialCompletionPercent: 85.71;
  productionAcceptance: "NOT_GRANTED";
  checks: WatchdogChecks;
};

export function buildWatchdogState(
  previous: WatchdogState | undefined,
  checks: WatchdogChecks,
  checkedAt = new Date(),
): WatchdogState {
  const failures = Object.entries(checks)
    .filter(([, check]) => !check.ok)
    .map(([name, check]) => `${name}: ${check.detail}`);
  const consecutiveFailures = failures.length === 0 ? 0 : (previous?.consecutiveFailures ?? 0) + 1;
  return {
    schema: "radlina.v3.macos-watchdog/v1",
    checkedAt: checkedAt.toISOString(),
    deviceId: "macbook-main",
    activeStage: "P08",
    latestCommit: checks.gitCommit.ok ? checks.gitCommit.detail : null,
    latestSuccessfulTest: checks.lastTest.ok ? checks.lastTest.detail : null,
    latestError: failures.at(0) ?? null,
    connectionStatus: checks.tailscale.ok ? "CONNECTED" : "DEGRADED",
    status: failures.length === 0 ? "HEALTHY" : consecutiveFailures >= 3 ? "BLOCKED" : "DEGRADED",
    consecutiveFailures,
    officialCompletionPercent: 85.71,
    productionAcceptance: "NOT_GRANTED",
    checks,
  };
}

function command(executable: string, args: string[]): string {
  return execFileSync(executable, args, {
    encoding: "utf8",
    timeout: 20_000,
    maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function safeCheck(run: () => string): WatchdogCheck {
  try {
    const detail = run();
    return { ok: true, detail };
  } catch (error) {
    return {
      ok: false,
      detail: error instanceof Error ? error.message.split("\n", 1)[0]!.slice(0, 300) : "failed",
    };
  }
}

function launchd(label: string): WatchdogCheck {
  return safeCheck(() => {
    const output = command("/bin/launchctl", ["print", `gui/${process.getuid?.() ?? 0}/${label}`]);
    if (!/state = running/u.test(output)) throw new Error(`${label} is not running`);
    return `${label}:running`;
  });
}

function heartbeat(databaseFile: string, nowMs: number): WatchdogCheck {
  return safeCheck(() => {
    const db = new DatabaseSync(databaseFile, { readOnly: true });
    try {
      const row = db
        .prepare(
          "SELECT d.descriptor_json AS descriptor, MAX(h.signed_at_ms) AS signed_at FROM v3_devices d LEFT JOIN v3_p03_heartbeat_nonces h ON h.device_id=d.device_id WHERE d.device_id=? GROUP BY d.device_id",
        )
        .get("macbook-main") as { descriptor: string; signed_at: number | null } | undefined;
      if (!row || row.signed_at === null) throw new Error("no accepted signed heartbeat");
      const descriptor = JSON.parse(row.descriptor) as { trustState?: string };
      if (descriptor.trustState !== "trusted") throw new Error("device is not trusted");
      const ageMs = nowMs - row.signed_at;
      if (ageMs < 0 || ageMs > 120_000) throw new Error("accepted signed heartbeat is stale");
      return new Date(row.signed_at).toISOString();
    } finally {
      db.close();
    }
  });
}

function tailscale(): WatchdogCheck {
  return safeCheck(() => {
    const executable = [
      "/usr/local/bin/tailscale",
      "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    ].find((candidate) => {
      try {
        statSync(candidate);
        return true;
      } catch {
        return false;
      }
    });
    if (!executable) throw new Error("Tailscale CLI unavailable");
    const status = JSON.parse(command(executable, ["status", "--json"])) as {
      BackendState?: string;
      CurrentTailnet?: { Name?: string };
      Self?: { Online?: boolean };
    };
    if (
      status.BackendState !== "Running" ||
      status.CurrentTailnet?.Name !== "rezanory.github" ||
      !status.Self?.Online
    ) {
      throw new Error("expected live Tailnet connection unavailable");
    }
    return "rezanory.github:connected";
  });
}

function lastTest(testEvidenceFile: string): WatchdogCheck {
  return safeCheck(() => {
    const evidence = JSON.parse(readFileSync(testEvidenceFile, "utf8")) as {
      status?: string;
      completedAt?: string;
      commit?: string;
    };
    if (evidence.status !== "PASS" || !evidence.completedAt || !evidence.commit) {
      throw new Error("latest test evidence is not a PASS");
    }
    return `${evidence.completedAt}@${evidence.commit.slice(0, 12)}`;
  });
}

function rotateLog(file: string, maxBytes = 1024 * 1024): void {
  try {
    if (statSync(file).size <= maxBytes) return;
    for (let index = 2; index >= 1; index -= 1) {
      const source = `${file}.${index}`;
      const destination = `${file}.${index + 1}`;
      try {
        renameSync(source, destination);
      } catch {
        // A missing older generation is normal.
      }
    }
    renameSync(file, `${file}.1`);
  } catch {
    // Missing log file is normal on first run.
  }
}

function readPrevious(file: string): WatchdogState | undefined {
  try {
    return JSON.parse(readFileSync(file, "utf8")) as WatchdogState;
  } catch {
    return undefined;
  }
}

function main(): void {
  if (process.platform !== "darwin") throw new Error("macOS watchdog requires macOS");
  const stateDirectory =
    process.env["RADLINA_WATCHDOG_STATE_DIRECTORY"] ??
    path.join(os.homedir(), ".local", "state", "radlina-v3", "watchdog");
  const repository = process.env["RADLINA_WATCHDOG_REPOSITORY"];
  if (!repository || !path.isAbsolute(repository)) throw new Error("absolute repository required");
  if (!path.isAbsolute(stateDirectory) || stateDirectory.toLowerCase().includes("v2")) {
    throw new Error("isolated V3 watchdog state directory required");
  }
  mkdirSync(stateDirectory, { recursive: true, mode: 0o700 });
  if (process.argv[2] === "record-test") {
    const commit = command("/usr/bin/git", ["-C", repository, "rev-parse", "HEAD"]);
    if (!/^[0-9a-f]{40}$/u.test(commit)) throw new Error("valid test commit required");
    writeFileSync(
      path.join(stateDirectory, "last-test.json"),
      JSON.stringify({ status: "PASS", completedAt: new Date().toISOString(), commit }, null, 2) +
        "\n",
      { mode: 0o600 },
    );
    process.stdout.write(JSON.stringify({ status: "PASS", commit }) + "\n");
    return;
  }
  const lockDirectory = path.join(stateDirectory, "run.lock");
  try {
    mkdirSync(lockDirectory, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const ageMs = Date.now() - statSync(lockDirectory).mtimeMs;
    if (ageMs <= 10 * 60_000) return;
    rmdirSync(lockDirectory);
    mkdirSync(lockDirectory, { mode: 0o700 });
  }

  try {
    const stateFile = path.join(stateDirectory, "status.json");
    const logFile = path.join(stateDirectory, "watchdog.log");
    rotateLog(logFile);
    const nowMs = Date.now();
    const checks: WatchdogChecks = {
      macOSAgent: launchd(
        process.env["RADLINA_MACOS_AGENT_LAUNCHD_LABEL"] ?? "com.radlina.remote-mcp.v3-agent",
      ),
      signedHeartbeat: heartbeat(
        process.env["RADLINA_P03_DATABASE"] ??
          path.join(os.homedir(), ".local", "share", "radlina", "v3-beta", "devices.sqlite3"),
        nowMs,
      ),
      githubRunner: launchd(
        process.env["RADLINA_GITHUB_RUNNER_LAUNCHD_LABEL"] ??
          "actions.runner.rezanory-radlina-remote-mcp.radlina-macbook-main",
      ),
      gitCommit: safeCheck(() => command("/usr/bin/git", ["-C", repository, "rev-parse", "HEAD"])),
      lastTest: lastTest(path.join(stateDirectory, "last-test.json")),
      tailscale: tailscale(),
    };
    const state = buildWatchdogState(readPrevious(stateFile), checks, new Date(nowMs));
    writeFileSync(stateFile, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
    writeFileSync(
      logFile,
      JSON.stringify({
        checkedAt: state.checkedAt,
        status: state.status,
        consecutiveFailures: state.consecutiveFailures,
        latestError: state.latestError,
      }) + "\n",
      { flag: "a", mode: 0o600 },
    );
    process.stdout.write(JSON.stringify(state) + "\n");
  } finally {
    rmdirSync(lockDirectory);
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(
      JSON.stringify({ error: error instanceof Error ? error.message : "watchdog failed" }) + "\n",
    );
    process.exitCode = 1;
  }
}
