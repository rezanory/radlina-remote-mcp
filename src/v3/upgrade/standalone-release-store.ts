import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, readFile, readdir, rename, rm, stat } from "node:fs/promises";
import path from "node:path";

import { RELEASE_MANIFEST_FILE, normalizeManifestId, releasePath, verifyReleaseRoot } from "../../admin/release-manifest.js";
import { AppError } from "../../errors.js";

/**
 * V3-only release store. Does not use V2 upgradeDirectory(), releaseRoot(),
 * productionRestart(), WinSW wrapper or process-global release pointers.
 * Mutation remains limited to the V3 release store; service activation is NOT
 * implemented here until a V3-only rollback mechanism is independently proven.
 */
export class V3StandaloneReleaseStore {
  private readonly releasesRoot: string;

  constructor(
    readonly root: string,
    prohibitedRoots: readonly string[],
  ) {
    if (!path.isAbsolute(root) || !root.trim()) throw new AppError("INVALID_INPUT", "V3 release root must be absolute");
    const normalize = (p: string): string => path.resolve(p).toLowerCase();
    const mine = normalize(root);
    for (const forbidden of prohibitedRoots) {
      const other = normalize(forbidden);
      if (mine === other || mine.startsWith(other + path.sep) || other.startsWith(mine + path.sep)) {
        throw new AppError("POLICY_DENIED", "V3 and V2 release/state roots must be disjoint");
      }
    }
    this.releasesRoot = path.join(root, "releases");
  }

  private release(manifest: string): string {
    return path.join(this.releasesRoot, normalizeManifestId(manifest));
  }

  async stage(sourceRoot: string, expectedManifest: string): Promise<unknown> {
    const manifest = normalizeManifestId(expectedManifest);
    const source = path.resolve(sourceRoot);
    if (!path.isAbsolute(sourceRoot) ||
      source.toLowerCase().startsWith(path.resolve(this.root).toLowerCase() + path.sep)) {
      throw new AppError("INVALID_INPUT", "V3 release source must be an independent absolute directory");
    }
    // All bytes are checked against the exact immutable manifest before copying.
    const verified = await verifyReleaseRoot(source, manifest);
    await mkdir(this.releasesRoot, { recursive: true });
    const lockRoot = path.join(this.root, "release-stage-locks");
    await mkdir(lockRoot, { recursive: true });
    const lock = path.join(lockRoot, manifest);
    try {
      await mkdir(lock);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new AppError("CONFLICT", "V3 release stage in progress; no automatic lock override");
      }
      throw error;
    }
    try {
      const target = this.release(manifest);
      const exists = await stat(target).then(() => true).catch((e: NodeJS.ErrnoException) => {
        if (e.code === "ENOENT") return false;
        throw e;
      });
      if (exists) {
        await verifyReleaseRoot(target, manifest);
        return { status: "STAGED", manifest, v3Only: true, idempotent: true };
      }
      const temp = path.join(this.releasesRoot, `.staging-${randomUUID()}`);
      await mkdir(temp);
      try {
        await copyFile(path.join(source, RELEASE_MANIFEST_FILE), path.join(temp, RELEASE_MANIFEST_FILE));
        for (const item of verified.manifest.files) {
          const to = releasePath(temp, item.path);
          await mkdir(path.dirname(to), { recursive: true });
          await copyFile(releasePath(source, item.path), to);
        }
        await verifyReleaseRoot(temp, manifest);
        await rename(temp, target);
      } catch (error) {
        await rm(temp, { recursive: true, force: true });
        throw error;
      }
      return {
        status: "STAGED", manifest, v3Only: true, idempotent: false,
        files: verified.manifest.files.length, sourceGitSha: verified.manifest.source.gitSha,
      };
    } finally {
      await rm(lock, { recursive: true });
    }
  }

  async verify(manifest: string): Promise<unknown> {
    const inspected = await verifyReleaseRoot(this.release(manifest), manifest);
    return {
      status: "PASS", v3Only: true, manifest: inspected.manifestId,
      sourceGitSha: inspected.manifest.source.gitSha, files: inspected.manifest.files.length,
      entry: inspected.manifest.entry, version: inspected.manifest.version,
    };
  }

  async preflight(manifest: string): Promise<unknown> {
    const inspected = await verifyReleaseRoot(this.release(manifest), manifest);
    if (inspected.manifest.entry !== "dist/scripts/operations/v3-oauth-readonly-daemon.js") {
      throw new AppError("INVALID_INPUT", "V3 release must have its dedicated OAuth service entry");
    }
    const entryBytes = await readFile(inspected.entryFile);
    if (entryBytes.length > 8 * 1024 * 1024) {
      throw new AppError("INVALID_INPUT", "V3 entry syntax probe size limit exceeded");
    }
    const checked = spawnSync(process.execPath, ["--check", "--input-type=module"], {
      input: entryBytes, windowsHide: true, timeout: 30_000,
      encoding: "utf8", maxBuffer: 16_384,
    });
    if (checked.error || checked.status !== 0) {
      throw new AppError("INVALID_INPUT", "V3 release entry syntax failed preflight");
    }
    return {
      status: "PASS", v3Only: true, manifest: inspected.manifestId,
      entry: inspected.manifest.entry, service: "RadlinaV3OAuthBeta",
      mutationPerformed: false,
    };
  }

  async status(): Promise<unknown> {
    const rootExists = await stat(this.releasesRoot).then((s) => s.isDirectory()).catch(() => false);
    const entries = rootExists ? await readdir(this.releasesRoot) : [];
    const staged = entries.filter((x) => /^[a-f0-9]{64}$/u.test(x)).sort();
    const xmlPath = path.join(this.root, "RadlinaV3OAuthBeta.xml");
    const xml = await readFile(xmlPath, "utf8").catch((e: NodeJS.ErrnoException) => {
      if (e.code === "ENOENT") return null;
      throw e;
    });
    let activeManifest: string | null = null;
    if (xml) {
      if (!/<id>RadlinaV3OAuthBeta<\/id>/u.test(xml)) {
        throw new AppError("CONFLICT", "V3 service XML is not for the standalone V3 service");
      }
      const working = /<workingdirectory>([^<]+)<\/workingdirectory>/u.exec(xml)?.[1]?.trim();
      if (working) {
        for (const manifest of staged) {
          if (path.resolve(working).toLowerCase() === path.resolve(this.release(manifest)).toLowerCase()) {
            activeManifest = manifest;
            break;
          }
        }
      }
    }
    return {
      service: "RadlinaV3OAuthBeta", v3Only: true, activeManifest,
      stagedManifests: staged, serviceDefinitionPresent: xml !== null,
      activationManagedSeparately: true,
    };
  }
}
