import { execFileSync } from "node:child_process";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign,
  verify,
} from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import * as z from "zod/v4";

import { protectBytes, unprotectBytes } from "../../auth/dpapi.js";
import { canonicalJson } from "../../utils/json.js";
import {
  ed25519PublicKeyFingerprint,
  type P03EnrollmentChallenge,
  type SignedAgentHeartbeat,
} from "./owner-pinned-enrollment.js";

const storedSchema = z.object({
  schema: z.literal("radlina.v3.windows-protected-identity/v1"),
  deviceId: z.literal("windows-main"),
  hostname: z.string().min(1),
  agentInstanceId: z.string().uuid(),
  agentVersion: z.literal("3.0.0-alpha.1"),
  publicKeyPem: z.string().max(4096),
  fingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
  protectedPrivateKey: z.string().min(1),
});
type Stored = z.infer<typeof storedSchema>;

/** Dedicated V3 key; never consumes V2 credentials. LocalMachine DPAPI requires this ACL. */
function assertPrivateDirectory(directory: string): void {
  if (process.platform !== "win32") throw new Error("physical Windows required");
  if (!path.isAbsolute(directory) || directory.includes("'") || directory.includes("\n"))
    throw new Error("absolute private directory required");
  const script = `$ErrorActionPreference='Stop'
$d='${directory}'
$a=Get-Acl -LiteralPath $d
if(-not $a.AreAccessRulesProtected){throw 'inherited ACL denied'}
$allowed=@('S-1-5-18','S-1-5-32-544')
foreach($r in $a.Access){
$s=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
if($r.IsInherited -or $r.AccessControlType -ne 'Allow' -or $s -notin $allowed){throw 'broad ACL denied'}
}
if($a.Access.Count -ne 2){throw 'private ACL incomplete'}
if((Get-Item -LiteralPath $d).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'reparse point denied'}
`;
  execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    timeout: 15000,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

export class WindowsProtectedDeviceIdentity {
  private constructor(
    private readonly stored: Stored,
    private readonly key: ReturnType<typeof createPrivateKey>,
  ) {}

  static async open(directory: string, provision = false): Promise<WindowsProtectedDeviceIdentity> {
    assertPrivateDirectory(directory);
    const file = path.join(directory, "device-identity.dpapi.json");
    let data: Stored;
    try {
      data = storedSchema.parse(JSON.parse(await readFile(file, "utf8")));
    } catch (error) {
      if (!provision || !(error instanceof Error) || !("code" in error) || error.code !== "ENOENT")
        throw error;
      const pair = generateKeyPairSync("ed25519");
      const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
      const raw = Buffer.from(pair.privateKey.export({ type: "pkcs8", format: "der" }));
      let protectedPrivateKey: string;
      try {
        protectedPrivateKey = await protectBytes(raw);
      } finally {
        raw.fill(0);
      }
      data = {
        schema: "radlina.v3.windows-protected-identity/v1",
        deviceId: "windows-main",
        hostname: os.hostname(),
        agentInstanceId: randomUUID(),
        agentVersion: "3.0.0-alpha.1",
        publicKeyPem,
        fingerprint: ed25519PublicKeyFingerprint(publicKeyPem),
        protectedPrivateKey,
      };
      await writeFile(file, JSON.stringify(data), { flag: "wx" });
    }
    const fileAclScript = `$ErrorActionPreference='Stop'
$f='${file}'
if((Get-Item -LiteralPath $f).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'identity reparse denied'}
$a=Get-Acl -LiteralPath $f
foreach($r in $a.Access){
$s=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
if($r.AccessControlType -ne 'Allow' -or $s -notin @('S-1-5-18','S-1-5-32-544')){throw 'broad identity ACL denied'}
}
if($a.Access.Count -lt 2){throw 'identity ACL incomplete'}
`;
    execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", fileAclScript], {
      timeout: 15000,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (data.hostname.toLowerCase() !== os.hostname().toLowerCase())
      throw new Error("host identity mismatch");
    if (ed25519PublicKeyFingerprint(data.publicKeyPem) !== data.fingerprint)
      throw new Error("public key tampering");
    const raw = await unprotectBytes(data.protectedPrivateKey);
    try {
      const key = createPrivateKey({ key: raw, type: "pkcs8", format: "der" });
      if (
        key.asymmetricKeyType !== "ed25519" ||
        ed25519PublicKeyFingerprint(
          createPublicKey(key).export({ type: "spki", format: "pem" }).toString(),
        ) !== data.fingerprint
      )
        throw new Error("protected key mismatch");
      return new WindowsProtectedDeviceIdentity(data, key);
    } finally {
      raw.fill(0);
    }
  }

  publicIdentity() {
    const { schema, deviceId, hostname, agentInstanceId, agentVersion, publicKeyPem, fingerprint } =
      this.stored;
    return { schema, deviceId, hostname, agentInstanceId, agentVersion, publicKeyPem, fingerprint };
  }

  signChallenge(challenge: P03EnrollmentChallenge): string {
    const s = this.stored;
    if (
      challenge.purpose !== "p03.owner-approved-enrollment" ||
      challenge.schema !== "1.0.0" ||
      challenge.deviceId !== s.deviceId ||
      challenge.hostname !== s.hostname ||
      challenge.platform !== "windows" ||
      challenge.architecture !== os.arch() ||
      challenge.agentInstanceId !== s.agentInstanceId ||
      challenge.agentVersion !== s.agentVersion ||
      challenge.deviceKeyFingerprint !== s.fingerprint ||
      !Number.isSafeInteger(challenge.issuedAtMs) ||
      !Number.isSafeInteger(challenge.expiresAtMs) ||
      challenge.issuedAtMs > Date.now() ||
      challenge.expiresAtMs <= Date.now() ||
      challenge.expiresAtMs - challenge.issuedAtMs > 600000 ||
      challenge.expiresAtMs <= challenge.issuedAtMs ||
      !z.string().uuid().safeParse(challenge.challengeId).success ||
      !/^[0-9a-f]{64}$/u.test(challenge.expectedTailnetNodeHash)
    )
      throw new Error("exact fresh Windows challenge required");
    return this.sign(challenge);
  }

  heartbeat(status: SignedAgentHeartbeat["status"], health: SignedAgentHeartbeat["health"]) {
    const s = this.stored;
    const heartbeat: SignedAgentHeartbeat = {
      schema: "radlina.v3.p03.signed-heartbeat/v1",
      deviceId: s.deviceId,
      agentInstanceId: s.agentInstanceId,
      agentVersion: s.agentVersion,
      signedAtMs: Date.now(),
      nonce: randomUUID(),
      status,
      health,
      capabilities: ["device.health"],
    };
    return { heartbeat, deviceSignatureBase64: this.sign(heartbeat) };
  }

  /**
   * P03 Windows-only signed target receipts and sessions.
   * No generic signing escape hatch and never signs Mac device messages.
   */
  signExactV3Receipt(payload: string): string {
    if (Buffer.byteLength(payload,"utf8") > 256*1024) {
      throw new Error("bounded Windows P03 V3 receipt required");
    }
    const value:unknown=JSON.parse(payload);
    if(!value||typeof value!=="object"||canonicalJson(value)!==payload) {
      throw new Error("canonical structured Windows P03 receipt required");
    }
    const document=value as Record<string,unknown>;
    const schema=document["schema"];
    const allowed=new Set([
      "radlina.v3.i01.device-session/v1",
      "radlina.v3.i01.recipient-approval/v1",
      "radlina.v3.i01.signed-device-response/v1",
      "radlina.v3.f01.signed-fleet-reply/v1",
      "radlina.v3.f01.recipient-release-consent/v1",
    ]);
    const s02e=schema==="1.0.0"&&document["action"]==="consent.decision";
    if((typeof schema!=="string"||(!allowed.has(schema)&&!s02e))||
      (document["deviceId"]!==undefined&&document["deviceId"]!=="windows-main")||
      (document["targetDeviceId"]!==undefined&&document["targetDeviceId"]!=="windows-main")||
      (document["resolvedDeviceId"]!==undefined&&document["resolvedDeviceId"]!=="windows-main")) {
      throw new Error("Windows P03 signer limited to exact Windows device-local receipts");
    }
    if(s02e&&document["targetDeviceId"]!=="windows-main") {
      throw new Error("S02E Windows P03 owner consent cannot target Mac");
    }
    return this.sign(value);
  }

  private sign(payload: unknown): string {
    const bytes = Buffer.from(canonicalJson(payload));
    const signature = sign(null, bytes, this.key);
    if (!verify(null, bytes, createPublicKey(this.stored.publicKeyPem), signature))
      throw new Error("local signature verification failed");
    return signature.toString("base64");
  }
}
