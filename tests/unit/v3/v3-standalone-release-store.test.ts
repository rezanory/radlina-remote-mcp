import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { RELEASE_MANIFEST_SCHEMA } from "../../../src/admin/release-manifest.js";
import { V3StandaloneReleaseStore } from "../../../src/v3/upgrade/standalone-release-store.js";

const sha = (v: string) => createHash("sha256").update(v).digest("hex");
const entry = "dist/scripts/operations/v3-oauth-readonly-daemon.js";
async function fixture(code = "export const v3Service = true;\n") {
  const root = await mkdtemp(path.join(tmpdir(), "v3-release-only-"));
  const v2State = path.join(root, "v2-state");
  const v3Root = path.join(root, "isolated-v3");
  const source = path.join(root, "src");
  const file = path.join(source, ...entry.split("/"));
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, code);
  const content = JSON.stringify({
    schema: RELEASE_MANIFEST_SCHEMA, version: "3.0.0-test", entry,
    source: { gitSha: "a".repeat(40), gitTree: "b".repeat(40), branch: "feature/v3-v2-parity" },
    evidence: [{ name: "test", bytes: 2, sha256: sha("ok") }],
    files: [{ path: entry, bytes: Buffer.byteLength(code), sha256: sha(code) }],
  }, null, 2) + "\n";
  const manifest = sha(content);
  await writeFile(path.join(source, "RELEASE_MANIFEST.json"), content);
  const store = new V3StandaloneReleaseStore(v3Root, [v2State]);
  return { root, v2State, v3Root, source, file, manifest, store };
}

describe("V3-only immutable release store", () => {
  it("stages, hashes, syntax-checks and lists ONLY an independent V3 release", async () => {
    const f = await fixture();
    try {
      expect(await f.store.stage(f.source, f.manifest)).toMatchObject({
        status: "STAGED", v3Only: true, idempotent: false, manifest: f.manifest,
      });
      expect(await f.store.stage(f.source, f.manifest)).toMatchObject({
        status: "STAGED", idempotent: true,
      });
      expect(await f.store.verify(f.manifest)).toMatchObject({ status: "PASS", v3Only: true });
      expect(await f.store.preflight(f.manifest)).toMatchObject({
        status: "PASS", service: "RadlinaV3OAuthBeta", mutationPerformed: false,
      });
      expect(await f.store.status()).toMatchObject({
        service: "RadlinaV3OAuthBeta", activeManifest: null, stagedManifests: [f.manifest],
      });
      await expect(readFile(path.join(f.v2State, "upgrade", "active-release.json"))).rejects.toThrow();
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });

  it("rejects tampered content, invalid hash, release store overlap and syntax errors", async () => {
    const f = await fixture();
    try {
      expect(() => new V3StandaloneReleaseStore(f.v2State, [f.v2State])).toThrow(/disjoint/u);
      await expect(f.store.stage(f.source, "0".repeat(64))).rejects.toThrow(/HASH_MISMATCH/u);
      await writeFile(f.file, "unmanifested bytes");
      await expect(f.store.stage(f.source, f.manifest)).rejects.toThrow(/MISMATCH/u);
      expect((await f.store.status() as { stagedManifests: string[] }).stagedManifests).toEqual([]);
    } finally { await rm(f.root, { recursive: true, force: true }); }
    const invalid = await fixture("export const = ;\n");
    try {
      await invalid.store.stage(invalid.source, invalid.manifest);
      await expect(invalid.store.preflight(invalid.manifest)).rejects.toThrow(/syntax/u);
    } finally { await rm(invalid.root, { recursive: true, force: true }); }
  });
});
