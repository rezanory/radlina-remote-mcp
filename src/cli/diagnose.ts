import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";

import { closeRuntime, createRuntime } from "../runtime.js";

const execFile = promisify(execFileCallback);

async function main(): Promise<void> {
  const runtime = await createRuntime(undefined, { reconcileSessions: false });
  try {
    const audit = await runtime.audit.verify(await runtime.audit.files());
    const { stdout: ripgrep } = await execFile(
      runtime.config.dependencies.ripgrepExecutable,
      ["--version"],
      { windowsHide: true, timeout: 5000, maxBuffer: 8192 },
    );
    let localEndpoint: { reachable: boolean; status?: number } = { reachable: false };
    try {
      const response = await fetch(
        `http://${runtime.config.server.host}:${runtime.config.server.port}/mcp`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
          signal: AbortSignal.timeout(2000),
        },
      );
      localEndpoint = { reachable: true, status: response.status };
    } catch {
      // The service may intentionally be stopped during offline diagnostics.
    }
    console.log(
      JSON.stringify(
        {
          healthy: audit.valid,
          node: process.version,
          ripgrep: ripgrep.split(/\r?\n/u)[0],
          config: {
            path: process.env["RADLINA_CONFIG"] ?? "config/local.yaml (with example fallback)",
            host: runtime.config.server.host,
            port: runtime.config.server.port,
            publicUrl: runtime.config.server.publicUrl,
            authMode: runtime.config.auth.mode,
            profiles: Object.keys(runtime.config.profiles),
          },
          controls: {
            killSwitch:
              runtime.store.get("control:killSwitch") ?? String(runtime.config.policy.killSwitch),
            emergencyReadOnly:
              runtime.store.get("control:emergencyReadOnly") ??
              String(runtime.config.policy.emergencyReadOnly),
          },
          audit,
          localEndpoint,
        },
        undefined,
        2,
      ),
    );
    if (!audit.valid) process.exitCode = 1;
  } finally {
    closeRuntime(runtime);
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "diagnostics failed");
  process.exitCode = 1;
});
