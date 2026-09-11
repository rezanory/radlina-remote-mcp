import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  parseReleaseManifest,
  RELEASE_MANIFEST_SCHEMA,
  type ReleaseManifest,
} from "../../src/admin/release-manifest.js";
import {
  confirmReleaseHealthy,
  mutationLockPath,
  prepareReleaseBoot,
  readActiveRelease,
  ROOT_RELEASE,
} from "../../src/admin/release-state.js";
import { UpgradeManager } from "../../src/admin/upgrade.js";
import { testConfig } from "../helpers/config.js";

const priorConfig = process.env["RADLINA_CONFIG"];
const cleanup: string[] = [];
const sha = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");

afterEach(async () => {
  if (priorConfig === undefined) delete process.env["RADLINA_CONFIG"];
  else process.env["RADLINA_CONFIG"] = priorConfig;
  delete process.env["RADLINA_ACTIVE_RELEASE_MANIFEST"];
  for (const directory of cleanup.splice(0)) {
    await rm(directory, { recursive: true, force: true });
  }
});

async function fixture(name: string): Promise<{
  root: string;
  configFile: string;
  manager: UpgradeManager;
  restarts: { count: number };
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), `radlina-up-${name}-`));
  cleanup.push(root);
  const configFile = path.join(root, "config", "local.yaml");
  await mkdir(path.dirname(configFile), { recursive: true });
  await mkdir(path.join(root, "service"), { recursive: true });
  await writeFile(path.join(root, "service", "RadlinaRemoteMCP.exe"), "winsw-fixture");
  process.env["RADLINA_CONFIG"] = configFile;
  const restarts = { count: 0 };
  const manager = new UpgradeManager(testConfig(root), configFile, () => {
    restarts.count += 1;
  });
  return { root, configFile, manager, restarts };
}

function manifestFor(name: string, entry: string, body: string): ReleaseManifest {
  return {
    schema: RELEASE_MANIFEST_SCHEMA,
    version: name,
    entry,
    source: {
      gitSha: "a".repeat(40),
      gitTree: "b".repeat(40),
      branch: "production/controller-full-control-v1",
    },
    evidence: [{ name: "unit", bytes: 2, sha256: sha("ok") }],
    files: [{ path: entry, bytes: Buffer.byteLength(body), sha256: sha(body) }],
  };
}

async function writeManifest(source: string, value: ReleaseManifest): Promise<string> {
  const raw = `${JSON.stringify(value, null, 2)}\n`;
  await writeFile(path.join(source, "RELEASE_MANIFEST.json"), raw);
  return sha(raw);
}

async function makeRelease(
  root: string,
  name: string,
  body: string,
): Promise<{ source: string; manifest: string; entryFile: string }> {
  const source = path.join(root, "workspace", name);
  const entry = "dist/src/app-entry.js";
  const entryFile = path.join(source, "dist", "src", "app-entry.js");
  await mkdir(path.dirname(entryFile), { recursive: true });
  await writeFile(entryFile, body);
  const manifest = await writeManifest(source, manifestFor(name, entry, body));
  return { source, manifest, entryFile };
}

async function activateAndConfirm(manager: UpgradeManager, manifest: string): Promise<void> {
  await manager.activate(manifest);
  const boot = await prepareReleaseBoot();
  expect(boot).toMatchObject({ manifest, pending: true });
  await confirmReleaseHealthy();
  const active = await readActiveRelease();
  expect(active).toMatchObject({ manifest, pending: false, attempts: 0 });
  await expect(manager.verifyPostRestart(manifest)).resolves.toMatchObject({
    status: "PASS",
    manifest,
  });
}

describe("UpgradeManager", () => {
  it("performs ROOT to A, rollback to ROOT, and exact A re-promotion", async () => {
    const { root, manager, restarts } = await fixture("root-cycle");
    const release = await makeRelease(root, "release-a", "export async function runApp(){}\n");
    await expect(manager.stage(release.source, release.manifest)).resolves.toMatchObject({
      status: "STAGED",
      manifest: release.manifest,
    });
    await expect(manager.preflight(release.manifest)).resolves.toMatchObject({
      status: "PASS",
      rdcRequired: false,
      runnerRequired: false,
    });
    await activateAndConfirm(manager, release.manifest);

    await expect(manager.rollback()).resolves.toMatchObject({
      status: "ROLLBACK_SCHEDULED",
      manifest: ROOT_RELEASE,
    });
    expect(await prepareReleaseBoot()).toMatchObject({ manifest: ROOT_RELEASE, pending: true });
    await confirmReleaseHealthy();
    expect(await readActiveRelease()).toMatchObject({ manifest: ROOT_RELEASE, pending: false });
    await expect(manager.verifyPostRestart(ROOT_RELEASE)).resolves.toMatchObject({
      status: "PASS",
      manifest: ROOT_RELEASE,
    });

    await activateAndConfirm(manager, release.manifest);
    expect(restarts.count).toBe(3);
  });

  it("automatically rolls back an unconfirmed B release to healthy A without cascading", async () => {
    const { root, manager } = await fixture("auto-rollback");
    const a = await makeRelease(root, "release-a", "export async function runApp(){}\n");
    const b = await makeRelease(
      root,
      "release-b",
      "export async function runApp(){throw new Error('boom')}\n",
    );
    await manager.stage(a.source, a.manifest);
    await activateAndConfirm(manager, a.manifest);
    await manager.stage(b.source, b.manifest);
    await manager.activate(b.manifest);
    expect(await prepareReleaseBoot()).toMatchObject({ manifest: b.manifest, pending: true });
    const recovered = await prepareReleaseBoot();
    expect(recovered).toMatchObject({ manifest: a.manifest, pending: false });
    expect(await readActiveRelease()).toMatchObject({
      manifest: a.manifest,
      pending: false,
      attempts: 0,
      transition: "AUTO_ROLLBACK",
    });
    expect(await prepareReleaseBoot()).toMatchObject({ manifest: a.manifest, pending: false });
    await expect(manager.verifyPostRestart(a.manifest)).resolves.toMatchObject({
      status: "PASS",
      manifest: a.manifest,
    });
  });

  it("restores ROOT as a stable baseline after an unconfirmed first release", async () => {
    const { root, manager } = await fixture("auto-rollback-root");
    const broken = await makeRelease(
      root,
      "release-broken",
      "export async function runApp(){throw new Error('boom')}\n",
    );
    await manager.stage(broken.source, broken.manifest);
    await manager.activate(broken.manifest);
    expect(await prepareReleaseBoot()).toMatchObject({ manifest: broken.manifest, pending: true });
    expect(await prepareReleaseBoot()).toMatchObject({ manifest: ROOT_RELEASE, pending: false });
    expect(await readActiveRelease()).toMatchObject({
      manifest: ROOT_RELEASE,
      previousManifest: ROOT_RELEASE,
      pending: false,
      attempts: 0,
      transition: "AUTO_ROLLBACK",
    });
    expect(await prepareReleaseBoot()).toMatchObject({ manifest: ROOT_RELEASE, pending: false });
    await expect(manager.verifyPostRestart(ROOT_RELEASE)).resolves.toMatchObject({
      status: "PASS",
      manifest: ROOT_RELEASE,
    });
  });

  it("rejects stale identity, wrong file hash, extra files, and a live mutation lock", async () => {
    const { root, manager } = await fixture("negative-content");
    const stale = await makeRelease(root, "stale", "export const value = 1;\n");
    await expect(manager.stage(stale.source, "0".repeat(64))).rejects.toThrow(
      "RELEASE_MANIFEST_HASH_MISMATCH",
    );

    const wrongHash = await makeRelease(root, "wrong-hash", "export const value = 1;\n");
    await writeFile(wrongHash.entryFile, "export const value = 2;\n");
    await expect(manager.stage(wrongHash.source, wrongHash.manifest)).rejects.toThrow(
      /RELEASE_FILE_(SIZE|HASH)_MISMATCH/u,
    );

    const extra = await makeRelease(root, "extra", "export const value = 1;\n");
    await writeFile(path.join(extra.source, "extra.txt"), "not-bound");
    await expect(manager.stage(extra.source, extra.manifest)).rejects.toThrow(
      "RELEASE_FILE_SET_MISMATCH",
    );

    const locked = await makeRelease(root, "locked", "export const value = 1;\n");
    await mkdir(path.dirname(mutationLockPath()), { recursive: true });
    await writeFile(
      mutationLockPath(),
      `${JSON.stringify({
        schema: "radlina.upgrade-lock.v1",
        token: "fixture",
        pid: process.pid,
        operation: "fixture",
        acquiredAt: new Date().toISOString(),
        acquiredAtMs: Date.now(),
      })}\n`,
    );
    await expect(manager.stage(locked.source, locked.manifest)).rejects.toThrow(
      "UPGRADE_IN_PROGRESS",
    );
  });

  it.each([
    "../escape.js",
    "/absolute.js",
    "C:/absolute.js",
    "//server/share.js",
    "dist/file.js:stream",
    "dist/CON.txt",
    "dist/trailing. ",
    "dist\\backslash.js",
  ])("rejects unsafe manifest path %s", (unsafe) => {
    const body = "export const value = 1;\n";
    const manifest = manifestFor("unsafe", unsafe, body);
    expect(() => parseReleaseManifest(`${JSON.stringify(manifest)}\n`)).toThrow(
      "INVALID_RELEASE_PATH",
    );
  });

  it("rejects case-insensitive duplicates, unsorted files, and an unbound entry", () => {
    const body = "x";
    const duplicate = manifestFor("duplicate", "dist/A.js", body);
    duplicate.files.push({ path: "dist/a.js", bytes: 1, sha256: sha(body) });
    expect(() => parseReleaseManifest(`${JSON.stringify(duplicate)}\n`)).toThrow(
      "DUPLICATE_RELEASE_FILE_CASE_INSENSITIVE",
    );

    const unsorted = manifestFor("unsorted", "z.js", body);
    unsorted.files.push({ path: "a.js", bytes: 1, sha256: sha(body) });
    expect(() => parseReleaseManifest(`${JSON.stringify(unsorted)}\n`)).toThrow(
      "UNSORTED_RELEASE_FILES",
    );

    const unbound = manifestFor("unbound", "entry.js", body);
    unbound.entry = "other.js";
    expect(() => parseReleaseManifest(`${JSON.stringify(unbound)}\n`)).toThrow(
      "RELEASE_ENTRY_NOT_MANIFEST_BOUND",
    );
  });

  it("fails preflight for a syntax-invalid entry", async () => {
    const { root, manager } = await fixture("syntax");
    const release = await makeRelease(root, "syntax", "export const = ;\n");
    await manager.stage(release.source, release.manifest);
    await expect(manager.preflight(release.manifest)).rejects.toThrow(
      "RELEASE_ENTRY_SYNTAX_CHECK_FAILED",
    );
  });

  it("keeps the raw manifest immutable when reading it", async () => {
    const { root } = await fixture("raw");
    const release = await makeRelease(root, "raw", "export const value = 1;\n");
    const before = await readFile(path.join(release.source, "RELEASE_MANIFEST.json"), "utf8");
    parseReleaseManifest(before);
    expect(await readFile(path.join(release.source, "RELEASE_MANIFEST.json"), "utf8")).toBe(before);
  });
});
