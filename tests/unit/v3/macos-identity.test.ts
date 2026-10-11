import { createPublicKey, verify } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { canonicalJson } from "../../../src/utils/json.js";
import { MacOSKeychainSecretProtector } from "../../../src/v3/device/macos-agent.js";
import { MacOSDeviceIdentityStore } from "../../../src/v3/device/macos-identity.js";

const roots: string[] = [];

function fakeKeychain(values = new Map<string, string>()) {
  let next = 0;
  const protector = new MacOSKeychainSecretProtector(
    "com.radlina.test.identity",
    async (args) => {
      const account = args[args.indexOf("-a") + 1];
      if (!account) throw new Error("missing account");
      if (args[0] === "add-generic-password") {
        values.set(account, args[args.indexOf("-w") + 1] ?? "");
        return "";
      }
      if (args[0] === "find-generic-password") {
        const value = values.get(account);
        if (!value) throw new Error("not found");
        return value;
      }
      if (args[0] === "delete-generic-password") {
        values.delete(account);
        return "";
      }
      throw new Error("unexpected Keychain command");
    },
    () => `00000000-0000-4000-8000-${String(++next).padStart(12, "0")}`,
  );
  return { protector, values };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("real macOS Ed25519 identity storage", () => {
  it("keeps the private key in Keychain and reloads the same signing identity", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "radlina-mac-identity-"));
    roots.push(root);
    const stateFile = path.join(root, "identity.json");
    const keychain = fakeKeychain();
    const store = new MacOSDeviceIdentityStore(
      stateFile,
      keychain.protector,
      () => new Date("2026-10-11T01:00:00.000Z"),
      () => "4c7208a8-f6a3-475d-84f9-f0bf9ddc0f9e",
    );

    const first = await store.ensure("macbook-main", "3.0.0-alpha.1");
    const second = await store.ensure("macbook-main", "3.0.0-alpha.1");
    expect(second.state).toEqual(first.state);
    expect(keychain.values.size).toBe(1);
    expect((await stat(stateFile)).mode & 0o777).toBe(0o600);

    const disk = await readFile(stateFile, "utf8");
    expect(disk).not.toContain([...keychain.values.values()][0]);
    expect(disk).not.toContain("PRIVATE KEY");

    const payload = { challengeId: "p08", deviceId: "macbook-main" };
    const signature = second.signCanonical(payload);
    expect(
      verify(
        null,
        Buffer.from(canonicalJson(payload), "utf8"),
        createPublicKey(second.state.publicKeyPem),
        Buffer.from(signature, "base64"),
      ),
    ).toBe(true);
  });

  it("fails closed for a public-state/keychain mismatch or insecure state permissions", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "radlina-mac-identity-"));
    roots.push(root);
    const keychain = fakeKeychain();
    const firstFile = path.join(root, "first.json");
    const secondFile = path.join(root, "second.json");
    const first = new MacOSDeviceIdentityStore(firstFile, keychain.protector);
    const second = new MacOSDeviceIdentityStore(secondFile, keychain.protector);
    await first.ensure("macbook-main", "3.0.0-alpha.1");
    await second.ensure("macbook-main", "3.0.0-alpha.1");

    const firstState = JSON.parse(await readFile(firstFile, "utf8")) as Record<string, unknown>;
    const secondState = JSON.parse(await readFile(secondFile, "utf8")) as Record<string, unknown>;
    firstState["keychainReference"] = secondState["keychainReference"];
    await writeFile(firstFile, JSON.stringify(firstState), { mode: 0o600 });
    await expect(first.ensure("macbook-main", "3.0.0-alpha.1")).rejects.toThrow(/does not match/u);

    await chmod(firstFile, 0o644);
    await expect(first.ensure("macbook-main", "3.0.0-alpha.1")).rejects.toThrow(/mode 0600/u);
  });
});
