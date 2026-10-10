import { randomBytes } from "node:crypto";
import os from "node:os";
import path from "node:path";

import { startLocalV3BetaGateway } from "../../src/v3/gateway/beta.js";

/**
 * V3 read-only local side-by-side bootstrap. This is intentionally NOT the
 * production V3 ChatGPT OAuth endpoint. No user/operator mutation is enabled.
 */
const rawPort = process.env["RADLINA_V3_BETA_PORT"] ?? "7343";
if (!/^\d{4,5}$/u.test(rawPort)) throw new Error("V3 beta port must be an explicit local port");
const port = Number(rawPort);
if (![7343, 7344].includes(port)) {
  throw new Error("V3 beta launcher permits only dedicated ports 7343 or 7344");
}

const localAppData = process.env["LOCALAPPDATA"];
const stateDirectory =
  process.env["RADLINA_V3_BETA_STATE_DIRECTORY"] ??
  path.resolve(localAppData || os.tmpdir(), "Radlina", "V3BetaStandalone");

const token = randomBytes(48).toString("hex");
const gateway = await startLocalV3BetaGateway({ port, stateDirectory, bearerToken: token });

const authenticated = await fetch(gateway.healthUrl, {
  headers: { authorization: `Bearer ${token}` },
  signal: AbortSignal.timeout(5000),
});
const anonymous = await fetch(gateway.healthUrl, {
  signal: AbortSignal.timeout(5000),
});
const health = (await authenticated.json()) as {
  mode?: string;
  productionReady?: boolean;
  enrolledDeviceCount?: number;
};

if (
  authenticated.status !== 200 ||
  anonymous.status !== 401 ||
  health.productionReady !== false ||
  health.enrolledDeviceCount !== 0
) {
  await gateway.shutdown();
  throw new Error("V3 local beta initial self-probe was not fail-closed");
}

process.stdout.write(
  JSON.stringify({
    mode: "v3-independent-local-readonly",
    version: "3.0.0-alpha.1",
    processId: process.pid,
    localEndpoint: gateway.url,
    bind: "127.0.0.1",
    port,
    auth: "ephemeral local-only bearer (never printed or persisted)",
    anonymousDenied: true,
    operatorExecution: "DISABLED",
    productionReady: false,
    enrolledDevices: 0,
    v2Service: "NOT_MODIFIED",
  }) + "\n",
);

let stopping = false;
const shutdown = (): void => {
  if (stopping) return;
  stopping = true;
  void gateway.shutdown().catch(() => {
    process.exitCode = 1;
  });
};
process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
