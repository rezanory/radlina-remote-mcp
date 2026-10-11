import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign,
  type KeyObject,
} from "node:crypto";
import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import * as z from "zod/v4";

import { canonicalJson } from "../../utils/json.js";
import { ed25519PublicKeyFingerprint } from "./owner-pinned-enrollment.js";
import { MacOSKeychainSecretProtector } from "./macos-agent.js";

const identityStateSchema = z.object({
  schema: z.literal("radlina.v3.macos-device-identity/v1"),
  deviceId: z.string().min(1).max(64),
  agentInstanceId: z.string().uuid(),
  agentVersion: z.string().min(1).max(128),
  publicKeyPem: z.string().includes("BEGIN PUBLIC KEY").max(4_096),
  publicKeyFingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
  keychainReference: z.string().regex(/^keychain:[0-9a-f-]{36}$/u),
  createdAt: z.string().datetime(),
});

export type MacOSDeviceIdentityState = z.infer<typeof identityStateSchema>;

export type MacOSDeviceIdentity = {
  state: MacOSDeviceIdentityState;
  signCanonical(payload: unknown): string;
};

/**
 * Persists only the public identity and an opaque Keychain reference on disk.
 * The Ed25519 PKCS#8 private key is generated locally and remains in Keychain.
 */
export class MacOSDeviceIdentityStore {
  constructor(
    private readonly stateFile: string,
    private readonly keychain: MacOSKeychainSecretProtector,
    private readonly now: () => Date = () => new Date(),
    private readonly uuid: () => string = () => randomUUID(),
  ) {
    if (!path.isAbsolute(stateFile)) throw new Error("absolute macOS identity state path required");
  }

  async ensure(deviceId: string, agentVersion: string): Promise<MacOSDeviceIdentity> {
    const existing = await this.readExisting();
    if (existing) {
      if (existing.deviceId !== deviceId || existing.agentVersion !== agentVersion) {
        throw new Error("stored macOS identity does not match requested device and agent version");
      }
      return await this.hydrate(existing);
    }

    const pair = generateKeyPairSync("ed25519");
    const privateDer = pair.privateKey.export({ type: "pkcs8", format: "der" });
    const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    const reference = await this.keychain.protect(privateDer);
    const state = identityStateSchema.parse({
      schema: "radlina.v3.macos-device-identity/v1",
      deviceId,
      agentInstanceId: this.uuid(),
      agentVersion,
      publicKeyPem,
      publicKeyFingerprint: ed25519PublicKeyFingerprint(publicKeyPem),
      keychainReference: Buffer.from(reference).toString("utf8"),
      createdAt: this.now().toISOString(),
    });

    await mkdir(path.dirname(this.stateFile), { recursive: true, mode: 0o700 });
    const temporary = `${this.stateFile}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporary, canonicalJson(state) + "\n", { flag: "wx", mode: 0o600 });
      await rename(temporary, this.stateFile);
      await chmod(this.stateFile, 0o600);
    } catch (error) {
      await this.keychain.delete(reference).catch(() => undefined);
      throw error;
    }
    return this.withSigner(state, pair.privateKey);
  }

  private async readExisting(): Promise<MacOSDeviceIdentityState | undefined> {
    try {
      const info = await stat(this.stateFile);
      if (!info.isFile() || (info.mode & 0o077) !== 0) {
        throw new Error("macOS identity state must be a private regular file with mode 0600");
      }
      return identityStateSchema.parse(JSON.parse(await readFile(this.stateFile, "utf8")));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  }

  private async hydrate(state: MacOSDeviceIdentityState): Promise<MacOSDeviceIdentity> {
    const bytes = await this.keychain.unprotect(Buffer.from(state.keychainReference, "utf8"));
    let privateKey: KeyObject;
    try {
      privateKey = createPrivateKey({ key: Buffer.from(bytes), format: "der", type: "pkcs8" });
    } catch {
      throw new Error("macOS Keychain identity contains an invalid private key");
    }
    if (privateKey.asymmetricKeyType !== "ed25519") {
      throw new Error("macOS Keychain identity must be Ed25519");
    }
    const derivedPublic = createPublicKey(privateKey).export({ type: "spki", format: "pem" });
    const derivedPem = derivedPublic.toString();
    if (
      derivedPem !== state.publicKeyPem ||
      ed25519PublicKeyFingerprint(derivedPem) !== state.publicKeyFingerprint
    ) {
      throw new Error("macOS identity public state does not match the Keychain private key");
    }
    return this.withSigner(state, privateKey);
  }

  private withSigner(state: MacOSDeviceIdentityState, privateKey: KeyObject): MacOSDeviceIdentity {
    return {
      state,
      signCanonical: (payload) =>
        sign(null, Buffer.from(canonicalJson(payload), "utf8"), privateKey).toString("base64"),
    };
  }
}
