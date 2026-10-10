import { loadConfig } from "../../src/config/index.js";
import { startV3ReadOnlyOAuthGateway } from "../../src/v3/gateway/oauth-readonly.js";

/**
 * Separate V3 pre-enrollment OAuth MCP process; no write-capable tool is registered.
 * Requires a real owner-controlled public HTTPS origin and isolated state directory.
 * TLS is provided by a separately validated ingress; never expose localhost directly.
 */
const publicUrl = process.env["RADLINA_V3_PUBLIC_URL"];
const stateDirectory = process.env["RADLINA_V3_OAUTH_STATE_DIRECTORY"];
if (!publicUrl || !stateDirectory) {
  throw new Error("RADLINA_V3_PUBLIC_URL and RADLINA_V3_OAUTH_STATE_DIRECTORY are required");
}
if (new URL(publicUrl).protocol !== "https:") {
  throw new Error("V3 public MCP ingress must have HTTPS before daemon startup");
}
const baseConfig = await loadConfig();
const gateway = await startV3ReadOnlyOAuthGateway({
  baseConfig,
  publicUrl,
  stateDirectory,
  port: 7344,
});
try {
  const auth = await fetch("http://127.0.0.1:7344/auth-health", {
    signal: AbortSignal.timeout(5000),
  });
  const anonymous = await fetch(gateway.url, {
    method: "POST",
    signal: AbortSignal.timeout(5000),
  });
  if (
    auth.status !== 200 ||
    anonymous.status !== 401 ||
    ((await auth.json()) as { status?: string }).status !== "healthy"
  ) {
    throw new Error("V3 OAuth self-probe failed closed");
  }
} catch (error) {
  await gateway.shutdown();
  throw error;
}
process.stdout.write(
  JSON.stringify({
    version: "3.0.0-alpha.1",
    mode: "oauth-readonly-pre-enrollment",
    port: gateway.port,
    loopbackEndpoint: gateway.url,
    publicOriginConfigured: new URL(publicUrl).origin,
    publicTlsVerified: false,
    executableTools: 0,
    deviceEnrollmentLive: false,
    v2Service: "UNTOUCHED",
  }) + "\n",
);

let closing = false;
const close = (): void => {
  if (closing) return;
  closing = true;
  void gateway.shutdown().catch(() => {
    process.exitCode = 1;
  });
};
process.once("SIGINT", close);
process.once("SIGTERM", close);
