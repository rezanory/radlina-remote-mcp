#!/usr/bin/env node
/**
 * P08 persistent macOS signed-health sender.
 *
 * Never accepts remote work and never exposes the private Keychain signing key.
 * launchd runs this once per interval. The pinned signer supplies the only
 * signed input; any HTTP error is fail-closed and left for the next interval.
 */
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);
const sourceSha = "de625477bbbc60d37adcc690c082df53fe5e6d6f";
const expectedHost = "amirs-MacBook-Pro.local";
const endpoint = "https://v3-mcp.radlina.com/v3/agent/heartbeat";
const home = os.homedir();
const state = path.join(home, ".local", "share", "radlina", "v3-beta", "macbook-main-agent");
const signerRoot = path.join(state, "signer-" + sourceSha);
const receipts = path.join(state, "receipts");
const eventsFile = path.join(state, "heartbeat-events.jsonl");

function fail(message: string): never {
  throw new Error(message);
}
async function privateDirectory(directory: string): Promise<void> {
  const value = await stat(directory);
  if (!value.isDirectory() || (value.mode & 0o077) !== 0) {
    fail("a private 0700 macOS V3 directory is mandatory");
  }
}
async function audit(status: "delivered" | "blocked", code: string, signedAtMs: number | null): Promise<void> {
  await writeFile(eventsFile, JSON.stringify({
    schema: "radlina.v3.p08.local-sender-event/v1",
    time: new Date().toISOString(),
    deviceId: "macbook-main",
    status,
    code,
    signedAtMs,
  }) + "\n", { flag: "a", mode: 0o600 });
}
async function main(): Promise<void> {
  if (
    process.platform !== "darwin" ||
    process.arch !== "x64" ||
    os.hostname() !== expectedHost ||
    process.argv.length !== 2 ||
    process.env["RADLINA_V3_MAC_AGENT_SOURCE_SHA"] !== sourceSha
  ) fail("physical macOS and immutable pinned signer required");
  process.umask(0o077);
  await privateDirectory(state);
  await privateDirectory(signerRoot);
  await mkdir(receipts, { recursive: true, mode: 0o700 });
  await privateDirectory(receipts);
  const signer = path.join(signerRoot, "scripts", "enrollment", "v3-p08-headless-identity.ts");
  const tsx = path.join(signerRoot, "node_modules", "tsx", "dist", "cli.mjs");
  const { stdout: currentSha } = await execute("/usr/bin/git", ["rev-parse", "HEAD"], {
    cwd: signerRoot, timeout: 8000, maxBuffer: 2048,
  });
  if (currentSha.trim() !== sourceSha) fail("pinned Mac signer commit changed");
  const directory = await mkdtemp(path.join(receipts, "once-"));
  let signedAt: number | null = null;
  try {
    await execute(process.execPath, [tsx, signer], {
      cwd: signerRoot,
      env: {
        ...process.env,
        RADLINA_MAC_P03_ACTION: "heartbeat",
        RADLINA_MAC_P03_RECEIPT_DIRECTORY: directory,
      },
      timeout: 45000,
      maxBuffer: 8192,
    });
    const bytes = await readFile(path.join(directory, "p03-signed-heartbeat.json"));
    if (bytes.byteLength > 4096) fail("oversized Mac P03 signature envelope");
    const envelope: unknown = JSON.parse(bytes.toString("utf8"));
    if (!envelope || typeof envelope !== "object") fail("invalid Mac P03 envelope");
    const record = envelope as Record<string, unknown>;
    const hb = record["heartbeat"];
    if (!hb || typeof hb !== "object") fail("signed heartbeat missing");
    const heartbeat = hb as Record<string, unknown>;
    if (
      record["schema"] !== "radlina.v3.p03.heartbeat-evidence/v1" ||
      heartbeat["schema"] !== "radlina.v3.p03.signed-heartbeat/v1" ||
      heartbeat["deviceId"] !== "macbook-main" ||
      heartbeat["agentVersion"] !== "3.0.0-alpha.1" ||
      heartbeat["status"] !== "online" ||
      heartbeat["health"] !== "healthy" ||
      JSON.stringify(heartbeat["capabilities"]) !== '["device.health"]' ||
      typeof heartbeat["signedAtMs"] !== "number" ||
      Math.abs(Date.now() - heartbeat["signedAtMs"]) > 60000 ||
      typeof record["deviceSignatureBase64"] !== "string" ||
      record["deviceSignatureBase64"].length !== 88
    ) fail("Mac signing output violated pinned P03 contract");
    signedAt = heartbeat["signedAtMs"] as number;
    const url = new URL(endpoint);
    if (url.protocol !== "https:" || url.hostname !== "v3-mcp.radlina.com") {
      fail("only independent production V3 TLS origin allowed");
    }
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "accept": "application/json" },
      body: bytes,
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
    if (response.status !== 200) fail("P08 endpoint returned HTTP_" + response.status);
    const receipt: unknown = await response.json();
    if (
      !receipt || typeof receipt !== "object" ||
      (receipt as Record<string, unknown>)["acceptance"] !== "V3_P08_REAL_MAC_SIGNED_HEARTBEAT_ACCEPTED" ||
      (receipt as Record<string, unknown>)["deviceId"] !== "macbook-main" ||
      (receipt as Record<string, unknown>)["trustState"] !== "trusted" ||
      (receipt as Record<string, unknown>)["crossDeviceExecutionEnabled"] !== false
    ) fail("P08 gateway did not acknowledge admitted physical Mac");
    // Persist signed P03 evidence, not merely a mutable JSONL success flag.
    // The operator will independently verify the heartbeat using Keychain P03 identity.
    const acknowledgement={
      schema:"radlina.v3.p08.durable-heartbeat-ack/v1",
      envelope, gatewayReceipt:receipt, acknowledgedAtMs:Date.now(),
    };
    const body=JSON.stringify(acknowledgement)+"\n";
    if(Buffer.byteLength(body,"utf8")>8192)fail("oversized P08 signed acknowledgement");
    const pending=path.join(state,"heartbeat-latest-ack."+randomUUID()+".pending");
    await writeFile(pending,body,{flag:"wx",mode:0o600});
    await rename(pending,path.join(state,"heartbeat-latest-ack.json"));
    await audit("delivered", "signed_heartbeat_acknowledged", signedAt);
    process.stdout.write(JSON.stringify({
      outcome: "P08_SIGNED_MAC_HEARTBEAT_ACKNOWLEDGED",
      signedAtMs: signedAt,
      deviceId: "macbook-main",
      remoteExecutionEnabled: false,
    }) + "\n");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
try {
  await main();
} catch (error) {
  const reason = error instanceof Error ? error.message.slice(0, 180) : "unknown";
  try { await audit("blocked", reason, null); } catch { /* no bypass on audit failure */ }
  process.stderr.write(JSON.stringify({
    outcome: "P08_MAC_HEARTBEAT_FAILED_CLOSED",
    failureId: randomUUID(),
    reason,
  }) + "\n");
  process.exitCode = 1;
}
