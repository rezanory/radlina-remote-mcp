import { randomUUID } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { copyFile, mkdir, open, readFile, rename, rm, stat, unlink } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import type { AppConfig } from "../config/schema.js";
import { AppError } from "../errors.js";
import {
  normalizeManifestId,
  RELEASE_MANIFEST_FILE,
  releasePath,
  verifyReleaseRoot,
} from "./release-manifest.js";
import {
  ACTIVE_RELEASE_SCHEMA,
  type ActiveRelease,
  activeReleasePath,
  assertRuntimeRelease,
  journalPath,
  mutationLockPath,
  readActiveRelease,
  readUpgradeJournal,
  releaseRoot,
  releasesDirectory,
  resolveReleaseIdentity,
  ROOT_RELEASE,
  type ReleaseIdentity,
  upgradeDirectory,
  writeActiveRelease,
  writeUpgradeJournal,
} from "./release-state.js";

type MutationLock = {
  schema: "radlina.upgrade-lock.v1";
  token: string;
  pid: number;
  operation: string;
  acquiredAt: string;
  acquiredAtMs: number;
};

function fail(code: string, message = code): never {
  throw new AppError("INVALID_INPUT", message, { code });
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

function isReleaseIdentity(value: string): value is ReleaseIdentity {
  return value === ROOT_RELEASE || /^[0-9a-f]{64}$/.test(value);
}

export class UpgradeManager {
  private readonly serviceWrapper: string;

  constructor(
    private readonly config: AppConfig,
    configFile: string,
    private readonly restart: () => void = () => undefined,
  ) {
    const projectRoot = path.dirname(path.dirname(configFile));
    this.serviceWrapper = path.join(projectRoot, "service", "RadlinaRemoteMCP.exe");
  }

  static productionRestart(configFile: string): () => void {
    const root = path.dirname(path.dirname(configFile));
    const wrapper = path.join(root, "service", "RadlinaRemoteMCP.exe");
    return () => {
      const timer = setTimeout(() => {
        const child = spawn(wrapper, ["restart!"], {
          detached: true,
          stdio: "ignore",
          windowsHide: true,
        });
        child.unref();
      }, 750);
      timer.unref();
    };
  }

  scheduleRestart(): void {
    this.restart();
  }

  private async acquireMutationLock(operation: string): Promise<MutationLock> {
    await mkdir(upgradeDirectory(), { recursive: true });
    const lockFile = mutationLockPath();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const lock: MutationLock = {
        schema: "radlina.upgrade-lock.v1",
        token: randomUUID(),
        pid: process.pid,
        operation,
        acquiredAt: new Date().toISOString(),
        acquiredAtMs: Date.now(),
      };
      try {
        const handle = await open(lockFile, "wx", 0o600);
        try {
          await handle.writeFile(`${JSON.stringify(lock, null, 2)}\n`, "utf8");
          await handle.sync();
        } finally {
          await handle.close();
        }
        return lock;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }

      let existing: Partial<MutationLock> | null = null;
      try {
        existing = JSON.parse(await readFile(lockFile, "utf8")) as Partial<MutationLock>;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 25));
        try {
          existing = JSON.parse(await readFile(lockFile, "utf8")) as Partial<MutationLock>;
        } catch {
          existing = null;
        }
      }
      const valid =
        existing?.schema === "radlina.upgrade-lock.v1" &&
        typeof existing.token === "string" &&
        Number.isInteger(existing.pid) &&
        typeof existing.acquiredAtMs === "number";
      const live = valid && isProcessAlive(existing!.pid!);
      if (live) {
        throw new AppError("CONFLICT", "UPGRADE_IN_PROGRESS", {
          operation: existing?.operation ?? "unknown",
          pid: existing?.pid ?? null,
          acquiredAt: existing?.acquiredAt ?? null,
        });
      }
      const quarantine = path.join(
        upgradeDirectory(),
        `mutation.lock.stale.${Date.now()}.${randomUUID()}`,
      );
      try {
        await rename(lockFile, quarantine);
        await writeUpgradeJournal({
          status: "STALE_MUTATION_LOCK_QUARANTINED",
          quarantine,
          prior: existing,
        });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    throw new AppError("CONFLICT", "UPGRADE_IN_PROGRESS");
  }

  private async releaseMutationLock(lock: MutationLock): Promise<void> {
    try {
      const current = JSON.parse(
        await readFile(mutationLockPath(), "utf8"),
      ) as Partial<MutationLock>;
      if (current.token !== lock.token) {
        throw new AppError("CONFLICT", "UPGRADE_LOCK_IDENTITY_MISMATCH");
      }
      await unlink(mutationLockPath());
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }

  private async withMutationLock<T>(operation: string, handler: () => Promise<T>): Promise<T> {
    const lock = await this.acquireMutationLock(operation);
    try {
      return await handler();
    } finally {
      await this.releaseMutationLock(lock);
    }
  }

  private checkEntrySyntax(entryFile: string): void {
    const entryUrl = pathToFileURL(entryFile).href;
    const probe = `const selected = await import(${JSON.stringify(entryUrl)}); if (typeof selected.runApp !== "function") throw new Error("INVALID_RELEASE_ENTRY_EXPORT");`;
    const checked = spawnSync(process.execPath, ["--input-type=module", "--eval", probe], {
      windowsHide: true,
      timeout: 30_000,
      maxBuffer: 16_384,
      encoding: "utf8",
    });
    if (checked.error) {
      throw new AppError("INVALID_INPUT", "RELEASE_ENTRY_SYNTAX_CHECK_FAILED", {
        cause: checked.error.message,
      });
    }
    if (checked.status !== 0) {
      throw new AppError("INVALID_INPUT", "RELEASE_ENTRY_SYNTAX_CHECK_FAILED", {
        status: checked.status,
        stderr: checked.stderr.slice(0, 16_384),
      });
    }
  }

  async stage(sourceRoot: string, expectedManifest: string): Promise<unknown> {
    return this.withMutationLock("stage", async () => {
      const normalized = normalizeManifestId(expectedManifest);
      const source = path.resolve(sourceRoot);
      const verified = await verifyReleaseRoot(source, normalized);
      const target = releaseRoot(normalized);
      await mkdir(releasesDirectory(), { recursive: true });
      try {
        const existing = await verifyReleaseRoot(target, normalized);
        await writeUpgradeJournal({
          status: "STAGED",
          stagedManifest: normalized,
          version: existing.manifest.version,
          idempotent: true,
        });
        return {
          status: "STAGED",
          manifest: normalized,
          version: existing.manifest.version,
          files: existing.manifest.files.length,
          idempotent: true,
        };
      } catch (error) {
        const exists = await stat(target)
          .then(() => true)
          .catch(() => false);
        if (exists) throw error;
      }

      const temp = path.join(releasesDirectory(), `.staging-${randomUUID()}`);
      await mkdir(temp, { recursive: false });
      try {
        await copyFile(
          releasePath(source, RELEASE_MANIFEST_FILE),
          releasePath(temp, RELEASE_MANIFEST_FILE),
        );
        for (const item of verified.manifest.files) {
          const from = releasePath(source, item.path);
          const to = releasePath(temp, item.path);
          await mkdir(path.dirname(to), { recursive: true });
          await copyFile(from, to);
        }
        await verifyReleaseRoot(temp, normalized);
        await rename(temp, target);
      } catch (error) {
        await rm(temp, { recursive: true, force: true }).catch(() => undefined);
        throw error;
      }
      await writeUpgradeJournal({
        status: "STAGED",
        stagedManifest: normalized,
        version: verified.manifest.version,
        files: verified.manifest.files.length,
      });
      return {
        status: "STAGED",
        manifest: normalized,
        version: verified.manifest.version,
        files: verified.manifest.files.length,
        idempotent: false,
      };
    });
  }

  async verify(manifest: string): Promise<unknown> {
    const normalized = normalizeManifestId(manifest);
    const verified = await verifyReleaseRoot(releaseRoot(normalized), normalized);
    return {
      status: "PASS",
      manifest: normalized,
      version: verified.manifest.version,
      files: verified.manifest.files.length,
      entry: verified.manifest.entry,
      source: verified.manifest.source,
      evidence: verified.manifest.evidence,
    };
  }

  async preflight(manifest: string): Promise<unknown> {
    const normalized = normalizeManifestId(manifest);
    const verified = await verifyReleaseRoot(releaseRoot(normalized), normalized);
    const wrapper = await stat(this.serviceWrapper);
    if (!wrapper.isFile()) fail("SERVICE_WRAPPER_MISSING");
    this.checkEntrySyntax(verified.entryFile);
    return {
      status: "PASS",
      manifest: normalized,
      entry: verified.manifest.entry,
      source: verified.manifest.source,
      selfRestart: "WinSW restart!",
      rdcRequired: false,
      runnerRequired: false,
      externalShellRequired: false,
    };
  }

  async activate(manifest: string): Promise<unknown> {
    return this.withMutationLock("activate", async () => {
      const normalized = normalizeManifestId(manifest);
      const verified = await verifyReleaseRoot(releaseRoot(normalized), normalized);
      const current = await readActiveRelease();
      if (current?.manifest === normalized) {
        return {
          status: current.pending ? "PENDING_RESTART_HEALTH" : "ACTIVE",
          manifest: normalized,
          idempotent: true,
          restartScheduled: false,
        };
      }
      const runtimeIdentity = process.env["RADLINA_ACTIVE_RELEASE_MANIFEST"] ?? ROOT_RELEASE;
      if (!isReleaseIdentity(runtimeIdentity)) fail("INVALID_RUNTIME_RELEASE_IDENTITY");
      const previousManifest = current?.manifest ?? runtimeIdentity;
      await resolveReleaseIdentity(previousManifest);
      const pointer: ActiveRelease = {
        schema: ACTIVE_RELEASE_SCHEMA,
        manifest: normalized,
        entry: verified.entryFile,
        previousManifest,
        pending: true,
        attempts: 0,
        transition: "ACTIVATE",
        activatedAt: new Date().toISOString(),
      };
      await writeActiveRelease(pointer);
      await writeUpgradeJournal({
        status: "ACTIVATION_SCHEDULED",
        activeManifest: normalized,
        previousManifest,
      });
      this.scheduleRestart();
      return {
        status: "ACTIVATION_SCHEDULED",
        manifest: normalized,
        previousManifest,
        restartScheduled: true,
      };
    });
  }

  async rollback(): Promise<unknown> {
    return this.withMutationLock("rollback", async () => {
      const current = await readActiveRelease();
      if (!current) fail("ROLLBACK_TARGET_UNAVAILABLE");
      const target = current.previousManifest;
      if (target === current.manifest) fail("ROLLBACK_TARGET_UNAVAILABLE");
      const resolved = await resolveReleaseIdentity(target);
      const pointer: ActiveRelease = {
        schema: ACTIVE_RELEASE_SCHEMA,
        manifest: resolved.manifest,
        entry: resolved.entry,
        previousManifest: current.manifest,
        pending: true,
        attempts: 0,
        transition: "ROLLBACK",
        activatedAt: new Date().toISOString(),
      };
      await writeActiveRelease(pointer);
      await writeUpgradeJournal({
        status: "ROLLBACK_SCHEDULED",
        activeManifest: target,
        previousManifest: current.manifest,
      });
      this.scheduleRestart();
      return {
        status: "ROLLBACK_SCHEDULED",
        manifest: target,
        previousManifest: current.manifest,
        restartScheduled: true,
      };
    });
  }

  async status(): Promise<unknown> {
    const active = await readActiveRelease();
    const journal = await readUpgradeJournal();
    return {
      status: active?.pending ? "PENDING_RESTART_HEALTH" : "READY",
      active,
      journal,
      runtimeManifest: process.env["RADLINA_ACTIVE_RELEASE_MANIFEST"] ?? ROOT_RELEASE,
      defaultProfile: this.config.policy.defaultProfile,
      rdcRequired: false,
      runnerRequired: false,
    };
  }

  async verifyPostRestart(expectedManifest: string): Promise<unknown> {
    const normalized =
      expectedManifest === ROOT_RELEASE ? ROOT_RELEASE : normalizeManifestId(expectedManifest);
    const active = await assertRuntimeRelease(normalized);
    return {
      status: "PASS",
      manifest: normalized,
      rollbackTarget: active?.previousManifest ?? null,
      healthConfirmed: true,
      rdcRequired: false,
      runnerRequired: false,
      externalShellRequired: false,
    };
  }

  evidencePaths(): { activeRelease: string; journal: string; lock: string } {
    return {
      activeRelease: activeReleasePath(),
      journal: journalPath(),
      lock: mutationLockPath(),
    };
  }
}
