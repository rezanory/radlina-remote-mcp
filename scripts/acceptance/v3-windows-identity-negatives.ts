import { execFileSync } from "node:child_process";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { protectBytes } from "../../src/auth/dpapi.js";
import { ed25519PublicKeyFingerprint } from "../../src/v3/device/owner-pinned-enrollment.js";

import { WindowsProtectedDeviceIdentity } from "../../src/v3/device/windows-protected-identity.js";

const root = path.join("E:\\radlina-v3-runtime", "identity-negative-" + randomUUID());
await mkdir(root);
execFileSync(
  "powershell.exe",
  [
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    `$a=New-Object Security.AccessControl.DirectorySecurity;$a.SetAccessRuleProtection($true,$false);foreach($s in @('S-1-5-18','S-1-5-32-544')){$r=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($s)),'FullControl','ContainerInherit,ObjectInherit','None','Allow');$a.AddAccessRule($r)};Set-Acl -LiteralPath '${root}' -AclObject $a`,
  ],
  { stdio: "pipe" },
);
// A disposable test key; no production identity ciphertext is copied or relaxed.
const pair = generateKeyPairSync("ed25519");
const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
const raw = Buffer.from(pair.privateKey.export({ type: "pkcs8", format: "der" }));
let protectedPrivateKey: string;
try {
  protectedPrivateKey = await protectBytes(raw);
} finally {
  raw.fill(0);
}
const encrypted = {
  schema: "radlina.v3.windows-protected-identity/v1",
  deviceId: "windows-main",
  hostname: os.hostname(),
  agentInstanceId: randomUUID(),
  agentVersion: "3.0.0-alpha.1",
  publicKeyPem,
  fingerprint: ed25519PublicKeyFingerprint(publicKeyPem),
  protectedPrivateKey,
};

const file = path.join(root, "device-identity.dpapi.json");
const checks: Record<string, boolean> = {};
try {
  for (const [name, patch] of Object.entries({
    wrongHost: { hostname: "OTHER-HOST" },
    tamperedPublicFingerprint: { fingerprint: "0".repeat(64) },
    wrongDevice: { deviceId: "macbook-main" },
    corruptCiphertext: { protectedPrivateKey: "AAAA" },
  })) {
    await writeFile(file, JSON.stringify({ ...encrypted, ...patch }));
    try {
      await WindowsProtectedDeviceIdentity.open(root);
      checks[name] = false;
    } catch {
      checks[name] = true;
    }
  }
  await writeFile(file, JSON.stringify(encrypted));
  execFileSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `$a=Get-Acl -LiteralPath '${file}';$r=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')),'Read','Allow');$a.AddAccessRule($r);Set-Acl -LiteralPath '${file}' -AclObject $a`,
    ],
    { stdio: "pipe" },
  );
  try {
    await WindowsProtectedDeviceIdentity.open(root);
    checks["broadFileAcl"] = false;
  } catch {
    checks["broadFileAcl"] = true;
  }
  if (Object.values(checks).some((value) => !value))
    throw new Error("identity security negative failed");
  const receipt = {
    schema: "radlina.v3.windows-protected-identity-negative-real/v1",
    timestamp: new Date().toISOString(),
    checks,
    testsPassed: 5,
    testsFailed: 0,
    productionIdentityModified: false,
    productionIdentityRead: false,
    disposableTestKey: true,
    acceptance: "REAL_NEGATIVE_KEY_STORAGE_CHECKS_ONLY",
  };
  await writeFile(
    "governance/v3/validation/V3_WINDOWS_IDENTITY_SECURITY_ISOLATED_NEGATIVES_20261011.json",
    JSON.stringify(receipt, null, 2) + "\n",
    { flag: "wx" },
  );
  process.stdout.write(JSON.stringify(receipt) + "\n");
} finally {
  await rm(root, { recursive: true, force: true });
}
