import { execFileSync, spawn } from "node:child_process";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign,
} from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import * as z from "zod/v4";

import { canonicalJson } from "../../src/utils/json.js";
import { ed25519PublicKeyFingerprint } from "../../src/v3/device/owner-pinned-enrollment.js";

if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif")
  throw new Error("owner Windows machine required");
const principal = execFileSync("whoami.exe", [], { encoding: "utf8" }).trim();
if (principal.toLowerCase() !== "laptop-13qineif\\radlina")
  throw new Error("run locally as LAPTOP-13QINEIF\\Radlina; SYSTEM/runner cannot act as owner");
const mode = process.argv[2];
if (mode !== "init" && mode !== "sign") throw new Error("mode must be init or sign");
const directory = path.join(os.homedir(), "AppData", "Local", "Radlina", "V3", "owner-signing");
await mkdir(directory, { recursive: true });
if (directory.includes("'")) throw new Error("unsupported owner directory");
const sid = execFileSync(
  "powershell.exe",
  [
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
  ],
  { encoding: "utf8" },
).trim();
if (!/^S-1-5-21-(?:[0-9]+-){3}[0-9]+$/u.test(sid))
  throw new Error("interactive owner SID required");
const secureDirectory = `$ErrorActionPreference='Stop'
$d='${directory}'
if((Get-Item -LiteralPath $d).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'reparse point denied'}
$a=New-Object Security.AccessControl.DirectorySecurity
$a.SetOwner((New-Object Security.Principal.SecurityIdentifier('${sid}')))
$a.SetAccessRuleProtection($true,$false)
foreach($s in @('${sid}','S-1-5-18')){
$r=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($s)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
$a.AddAccessRule($r)
}
Set-Acl -LiteralPath $d -AclObject $a
`;
execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", secureDirectory], {
  stdio: "pipe",
});
async function dpapi(operation: "Protect" | "Unprotect", input: Buffer): Promise<Buffer> {
  const script = `$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$b=[Convert]::FromBase64String([Console]::In.ReadToEnd())
$o=[Security.Cryptography.ProtectedData]::${operation}($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($o))`;
  return await new Promise((resolve, reject) => {
    const child = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
      stdio: ["pipe", "pipe", "ignore"],
      windowsHide: true,
    });
    const chunks: Buffer[] = [];
    child.stdout.on("data", (b: Buffer) => chunks.push(b));
    child.on("error", () => reject(new Error("owner DPAPI failed")));
    child.on("close", (exit) =>
      exit === 0
        ? resolve(Buffer.from(Buffer.concat(chunks).toString(), "base64"))
        : reject(new Error("owner DPAPI denied")),
    );
    child.stdin.end(input.toString("base64"));
  });
}
const schema = z.object({
  schema: z.literal("radlina.v3.owner-current-user-key/v1"),
  ownerPrincipal: z.string(),
  ownerSid: z.string(),
  keyId: z.string().uuid(),
  publicKeyPem: z.string(),
  fingerprint: z.string(),
  protectedPrivateKey: z.string(),
});
const keyFile = path.join(directory, "owner.dpapi.json");
let stored: z.infer<typeof schema>;
try {
  stored = schema.parse(JSON.parse(await readFile(keyFile, "utf8")));
} catch (error) {
  if (mode !== "init" || !(error instanceof Error) || !("code" in error) || error.code !== "ENOENT")
    throw error;
  const pair = generateKeyPairSync("ed25519");
  const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const raw = Buffer.from(pair.privateKey.export({ type: "pkcs8", format: "der" }));
  let protectedKey: Buffer;
  try {
    protectedKey = await dpapi("Protect", raw);
  } finally {
    raw.fill(0);
  }
  stored = {
    schema: "radlina.v3.owner-current-user-key/v1",
    ownerPrincipal: principal,
    ownerSid: sid,
    keyId: randomUUID(),
    publicKeyPem,
    fingerprint: ed25519PublicKeyFingerprint(publicKeyPem),
    protectedPrivateKey: protectedKey.toString("base64"),
  };
  await writeFile(keyFile, JSON.stringify(stored), { flag: "wx" });
}
if (
  stored.ownerPrincipal !== principal ||
  stored.ownerSid !== sid ||
  ed25519PublicKeyFingerprint(stored.publicKeyPem) !== stored.fingerprint
)
  throw new Error("owner key binding mismatch");
const publicPin = {
  schema: "radlina.v3.owner-public-pin/v1",
  ownerPrincipal: principal,
  ownerSid: sid,
  keyId: stored.keyId,
  publicKeyPem: stored.publicKeyPem,
  fingerprint: stored.fingerprint,
};
await writeFile(
  path.join(directory, "owner-public-pin.json"),
  JSON.stringify(publicPin, null, 2) + "\n",
);
if (mode === "init") {
  process.stdout.write(
    JSON.stringify({
      status: "OWNER_CURRENT_USER_KEY_INITIALIZED",
      publicPinFile: path.join(directory, "owner-public-pin.json"),
      fingerprint: stored.fingerprint,
    }) + "\n",
  );
} else {
  const challengeFile = process.argv[3],
    outputFile = process.argv[4];
  if (
    !challengeFile ||
    !outputFile ||
    !path.isAbsolute(challengeFile) ||
    !path.isAbsolute(outputFile)
  )
    throw new Error("absolute challenge and public output paths required");
  const challenge = z
    .object({
      schema: z.literal("1.0.0"),
      purpose: z.literal("p03.owner-approved-enrollment"),
      challengeId: z.string().uuid(),
      deviceId: z.enum(["windows-main", "macbook-main"]),
      hostname: z.string(),
      platform: z.enum(["windows", "macos"]),
      architecture: z.enum(["x64", "arm64", "unknown"]),
      agentVersion: z.string(),
      agentInstanceId: z.string().uuid(),
      deviceKeyFingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
      expectedTailnetNodeHash: z.string().regex(/^[0-9a-f]{64}$/u),
      issuedAtMs: z.number().int(),
      expiresAtMs: z.number().int(),
    })
    .strict()
    .parse(JSON.parse(await readFile(challengeFile, "utf8")));
  const expected =
    challenge.deviceId === "windows-main"
      ? { host: "LAPTOP-13QINEIF", platform: "windows" }
      : { host: "amirs-MacBook-Pro.local", platform: "macos" };
  if (
    challenge.hostname !== expected.host ||
    challenge.platform !== expected.platform ||
    challenge.agentVersion !== "3.0.0-alpha.1" ||
    challenge.deviceKeyFingerprint === stored.fingerprint ||
    challenge.issuedAtMs > Date.now() ||
    challenge.expiresAtMs <= Date.now() ||
    challenge.expiresAtMs <= challenge.issuedAtMs ||
    challenge.expiresAtMs - challenge.issuedAtMs > 600000
  )
    throw new Error("exact fresh owner challenge required");
  const raw = await dpapi("Unprotect", Buffer.from(stored.protectedPrivateKey, "base64"));
  try {
    const key = createPrivateKey({ key: raw, type: "pkcs8", format: "der" });
    if (
      ed25519PublicKeyFingerprint(
        createPublicKey(key).export({ type: "spki", format: "pem" }).toString(),
      ) !== stored.fingerprint
    )
      throw new Error("owner protected key mismatch");
    const signature = sign(null, Buffer.from(canonicalJson(challenge)), key).toString("base64");
    await writeFile(
      outputFile,
      JSON.stringify({ publicPin, challenge, ownerSignatureBase64: signature }, null, 2) + "\n",
      { flag: "wx" },
    );
    process.stdout.write(
      JSON.stringify({
        status: "OWNER_CHALLENGE_SIGNED",
        outputFile,
        challengeId: challenge.challengeId,
      }) + "\n",
    );
  } finally {
    raw.fill(0);
  }
}
