import { readFileSync } from "node:fs";
import { loadConfig } from "../../src/config/index.js";
import { observeLiveMacTailnetPeer } from "../../src/v3/device/mac-heartbeat-ingress.js";
import { requireOwnerApprovedMacOperatorPolicy } from "../../src/v3/device/p08-mac-operator-policy.js";
import { finalFourFactoryFromOwnerEnvironment } from "../../src/v3/control-plane/v3-environment-factory.js";
import { startV3ReadOnlyOAuthGateway } from "../../src/v3/gateway/oauth-readonly.js";

/**
 * Independent V3 OAuth MCP process; scoped local Windows file operations are opt-in.
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
const enabled = process.env["RADLINA_V3_LOCAL_WINDOWS_FILES"] === "1";
const configuredRoot = process.env["RADLINA_V3_WINDOWS_FILE_ROOT"];
if (enabled && !configuredRoot) {
  throw new Error(
    "explicit RADLINA_V3_WINDOWS_FILE_ROOT required when enabling V3 local file operations",
  );
}
const macHeartbeatEnabled = process.env["RADLINA_V3_MAC_SIGNED_HEARTBEAT_ENABLED"] === "1";
const macOwnerPinPath =
  "C:\\Users\\Radlina\\AppData\\Local\\Radlina\\V3\\owner-signing\\owner-public-pin.json";
const macOwnerPublicPin = macHeartbeatEnabled
  ? (JSON.parse(readFileSync(macOwnerPinPath, "utf8")) as {
      publicKeyPem: string;
      fingerprint: string;
      ownerPrincipal: string;
    })
  : undefined;
if (
  macOwnerPublicPin &&
  (process.platform !== "win32" ||
    macOwnerPublicPin.ownerPrincipal.toLowerCase() !== "laptop-13qineif\\radlina" ||
    macOwnerPublicPin.fingerprint !==
      "6259d21211f73fc9d2d7cc0174d9bfdc36424cd456878671ab5683468ca0fe93")
) {
  throw new Error("V3 mac heartbeat requires exact independently verified Windows owner pin");
}
const operatorPolicyPath = process.env["RADLINA_V3_SIGNED_MAC_OPERATOR_POLICY_PATH"];
if (operatorPolicyPath && !macOwnerPublicPin) {
  throw new Error("Mac execution capability policy requires P03 owner-pinned heartbeat");
}
const approvedOperatorPolicy = operatorPolicyPath
  ? requireOwnerApprovedMacOperatorPolicy(
    JSON.parse(readFileSync(operatorPolicyPath, "utf8")),
  ) : undefined;
if (approvedOperatorPolicy && approvedOperatorPolicy.ownerPublicKeyPem !== macOwnerPublicPin?.publicKeyPem) {
  throw new Error("Mac operator capability policy must bind exact P03 owner public key");
}
const finalFourEnabled=process.env["RADLINA_V3_FINAL4_ENABLE"]==="1";
if(finalFourEnabled&&!approvedOperatorPolicy){
  throw new Error("V3 final-four requires the existing signed Mac P03 operator policy");
}
const finalFourFactory=finalFourEnabled
  ? finalFourFactoryFromOwnerEnvironment()
  : undefined;
let gateway:Awaited<ReturnType<typeof startV3ReadOnlyOAuthGateway>>;
try {
  gateway=await startV3ReadOnlyOAuthGateway({
  baseConfig,
  publicUrl,
  stateDirectory,
  port: 7344,
  ...(enabled && configuredRoot ? { windowsFileRoot: configuredRoot } : {}),
  ...(finalFourFactory ? { finalFourFactory } : {}),
  ...(macOwnerPublicPin
    ? {
        macHeartbeatPins: {
          ownerPublicKeyPem: macOwnerPublicPin.publicKeyPem,
          ownerKeyFingerprint: macOwnerPublicPin.fingerprint,
          macDeviceKeyFingerprint:
            "f2c2e93ff120fbc5122cbb6b5a0b461a072f54bd8d226368c858fd0bd17037ea",
          macTailnetNodeHash: "c7886ac103d4c05907ff8953ae60687d31303146a9b122cb55bff0dc1860bc9c",
          observeLiveMacTailnetNodeHash: observeLiveMacTailnetPeer,
      ...(approvedOperatorPolicy ? { approvedOperatorPolicy } : {}),
        },
      }
    : {}),
  });
} catch(error) {
  throw error;
}
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
    mode: enabled ? "oauth-scoped-windows-files" : "oauth-readonly-pre-enrollment",
    port: gateway.port,
    loopbackEndpoint: gateway.url,
    publicOriginConfigured: new URL(publicUrl).origin,
    publicTlsVerified: false,
    executableTools: enabled ? 1 : 0,
    localWindowsFileOperationsEnabled: enabled,
    macSignedHeartbeatIngressEnabled: macHeartbeatEnabled,
    finalFourPhysicalPortsConfigured: Boolean(finalFourFactory),
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
