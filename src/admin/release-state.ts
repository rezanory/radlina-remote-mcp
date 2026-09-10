import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import { configPath } from "../config/index.js";
import { AppError } from "../errors.js";
import { normalizeManifestId, verifyReleaseRoot } from "./release-manifest.js";

export const ROOT_RELEASE = "ROOT";
export const ACTIVE_RELEASE_SCHEMA = "radlina.active-release.v2";
const JOURNAL_SCHEMA = "radlina.upgrade-journal.v1";

export type ReleaseIdentity = string;
export type ActiveRelease = {
  schema: typeof ACTIVE_RELEASE_SCHEMA;
  manifest: ReleaseIdentity;
  entry: string | null;
  previousManifest: ReleaseIdentity;
  pending: boolean;
  attempts: number;
  transition: "ACTIVATE" | "ROLLBACK" | "AUTO_ROLLBACK";
  activatedAt: string;
  confirmedAt?: string;
};

export type UpgradeJournalEntry = Record<string, unknown> & {
  sequence?: number;
  timestampUtc?: string;
};

type UpgradeJournal = {
  schema: typeof JOURNAL_SCHEMA;
  entries: Array<Record<string, unknown> & { sequence: number; timestampUtc: string }>;
};

function projectRoot(): string {
  return path.dirname(path.dirname(configPath()));
}

export function upgradeDirectory(): string {
  return path.join(projectRoot(), ".state", "upgrade");
}

export function releasesDirectory(): string {
  return path.join(projectRoot(), ".state", "releases");
}

export function activeReleasePath(): string {
  return path.join(upgradeDirectory(), "active-release.json");
}

export function journalPath(): string {
  return path.join(upgradeDirectory(), "journal.json");
}

export function mutationLockPath(): string {
  return path.join(upgradeDirectory(), "mutation.lock");
}

async function atomicJson(file: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
  await rename(temp, file);
}

function validIdentity(value: unknown): value is ReleaseIdentity {
  return value === ROOT_RELEASE || (typeof value === "string" && /^[0-9a-f]{64}$/.test(value));
}

function parseActiveRelease(value: unknown): ActiveRelease {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("INVALID_ACTIVE_RELEASE_POINTER");
  }
  const parsed = value as Partial<ActiveRelease>;
  if (
    parsed.schema !== ACTIVE_RELEASE_SCHEMA ||
    !validIdentity(parsed.manifest) ||
    !(parsed.entry === null || typeof parsed.entry === "string") ||
    !validIdentity(parsed.previousManifest) ||
    typeof parsed.pending !== "boolean" ||
    !Number.isInteger(parsed.attempts) ||
    (parsed.attempts ?? -1) < 0 ||
    !["ACTIVATE", "ROLLBACK", "AUTO_ROLLBACK"].includes(parsed.transition ?? "") ||
    typeof parsed.activatedAt !== "string"
  ) {
    throw new Error("INVALID_ACTIVE_RELEASE_POINTER");
  }
  if (parsed.manifest === ROOT_RELEASE && parsed.entry !== null) {
    throw new Error("INVALID_ROOT_RELEASE_ENTRY");
  }
  return parsed as ActiveRelease;
}

export async function readActiveRelease(): Promise<ActiveRelease | null> {
  try {
    return parseActiveRelease(JSON.parse(await readFile(activeReleasePath(), "utf8")) as unknown);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

export async function writeActiveRelease(value: ActiveRelease): Promise<void> {
  parseActiveRelease(value);
  await atomicJson(activeReleasePath(), value);
}

export async function readUpgradeJournal(): Promise<UpgradeJournal> {
  try {
    const value = JSON.parse(await readFile(journalPath(), "utf8")) as Partial<UpgradeJournal>;
    if (value.schema !== JOURNAL_SCHEMA || !Array.isArray(value.entries)) {
      throw new Error("INVALID_UPGRADE_JOURNAL");
    }
    return value as UpgradeJournal;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { schema: JOURNAL_SCHEMA, entries: [] };
    }
    throw error;
  }
}

export async function writeUpgradeJournal(value: UpgradeJournalEntry): Promise<void> {
  const current = await readUpgradeJournal();
  const prior = current.entries.at(-1)?.sequence ?? 0;
  const entry = {
    ...value,
    sequence: prior + 1,
    timestampUtc: value.timestampUtc ?? new Date().toISOString(),
  };
  await atomicJson(journalPath(), {
    schema: JOURNAL_SCHEMA,
    entries: [...current.entries.slice(-255), entry],
  } satisfies UpgradeJournal);
}

export function releaseRoot(manifest: string): string {
  return path.join(releasesDirectory(), normalizeManifestId(manifest));
}

export async function resolveReleaseIdentity(
  manifest: ReleaseIdentity,
): Promise<{ manifest: ReleaseIdentity; entry: string | null; version: string }> {
  if (manifest === ROOT_RELEASE) {
    return { manifest, entry: null, version: "ROOT" };
  }
  const verified = await verifyReleaseRoot(releaseRoot(manifest), manifest);
  return {
    manifest: verified.manifestId,
    entry: verified.entryFile,
    version: verified.manifest.version,
  };
}

function sameEntry(left: string | null, right: string | null): boolean {
  if (left === null || right === null) return left === right;
  return path.resolve(left).toLowerCase() === path.resolve(right).toLowerCase();
}

export async function prepareReleaseBoot(): Promise<{
  manifest: ReleaseIdentity;
  entry: string | null;
  pending: boolean;
}> {
  let active = await readActiveRelease();
  if (!active) {
    process.env["RADLINA_ACTIVE_RELEASE_MANIFEST"] = ROOT_RELEASE;
    return { manifest: ROOT_RELEASE, entry: null, pending: false };
  }

  if (active.pending && active.attempts >= 1) {
    if (active.manifest === ROOT_RELEASE && active.previousManifest === ROOT_RELEASE) {
      throw new Error("ROOT_RECOVERY_FAILED");
    }
    const failedManifest = active.manifest;
    const recovered = await resolveReleaseIdentity(active.previousManifest);
    active = {
      schema: ACTIVE_RELEASE_SCHEMA,
      manifest: recovered.manifest,
      entry: recovered.entry,
      previousManifest: ROOT_RELEASE,
      pending: true,
      attempts: 1,
      transition: "AUTO_ROLLBACK",
      activatedAt: new Date().toISOString(),
    };
    await writeActiveRelease(active);
    await writeUpgradeJournal({
      status: "AUTO_ROLLBACK_BOOT",
      failedManifest,
      activeManifest: active.manifest,
    });
  } else if (active.pending) {
    active = { ...active, attempts: active.attempts + 1 };
    await writeActiveRelease(active);
    await writeUpgradeJournal({
      status: "BOOT_ATTEMPT",
      activeManifest: active.manifest,
      attempt: active.attempts,
      transition: active.transition,
    });
  }

  const resolved = await resolveReleaseIdentity(active.manifest);
  if (!sameEntry(active.entry, resolved.entry)) {
    throw new Error("ACTIVE_RELEASE_ENTRY_MISMATCH");
  }
  process.env["RADLINA_ACTIVE_RELEASE_MANIFEST"] = active.manifest;
  return { manifest: active.manifest, entry: resolved.entry, pending: active.pending };
}

export function armPendingHealthGate(
  manifest: ReleaseIdentity,
  timeoutMs = 30_000,
): NodeJS.Timeout {
  const timer = setTimeout(() => {
    void readActiveRelease()
      .then((active) => {
        if (active?.pending && active.manifest === manifest) process.exit(1);
      })
      .catch(() => process.exit(1));
  }, timeoutMs);
  timer.unref();
  return timer;
}

export async function confirmReleaseHealthy(): Promise<void> {
  const expected = process.env["RADLINA_ACTIVE_RELEASE_MANIFEST"] ?? ROOT_RELEASE;
  const active = await readActiveRelease();
  if (!active) {
    if (expected !== ROOT_RELEASE) throw new Error("ACTIVE_RELEASE_IDENTITY_MISMATCH");
    return;
  }
  if (active.manifest !== expected) throw new Error("ACTIVE_RELEASE_IDENTITY_MISMATCH");
  const resolved = await resolveReleaseIdentity(active.manifest);
  if (!sameEntry(active.entry, resolved.entry)) throw new Error("ACTIVE_RELEASE_ENTRY_MISMATCH");
  if (!active.pending) return;
  const confirmed: ActiveRelease = {
    ...active,
    pending: false,
    attempts: 0,
    confirmedAt: new Date().toISOString(),
  };
  await writeActiveRelease(confirmed);
  await writeUpgradeJournal({
    status: "ACTIVE_HEALTH_CONFIRMED",
    activeManifest: expected,
    previousManifest: active.previousManifest,
    transition: active.transition,
  });
}

export async function assertRuntimeRelease(
  expectedManifest: ReleaseIdentity,
): Promise<ActiveRelease | null> {
  const runtimeManifest = process.env["RADLINA_ACTIVE_RELEASE_MANIFEST"] ?? ROOT_RELEASE;
  if (runtimeManifest !== expectedManifest) {
    throw new AppError("CONFLICT", "RUNTIME_RELEASE_IDENTITY_MISMATCH");
  }
  const active = await readActiveRelease();
  if (!active) {
    if (expectedManifest !== ROOT_RELEASE) {
      throw new AppError("CONFLICT", "POST_RESTART_MANIFEST_MISMATCH");
    }
    return null;
  }
  if (active.manifest !== expectedManifest) {
    throw new AppError("CONFLICT", "POST_RESTART_MANIFEST_MISMATCH");
  }
  if (active.pending) throw new AppError("CONFLICT", "POST_RESTART_HEALTH_NOT_CONFIRMED");
  const resolved = await resolveReleaseIdentity(active.manifest);
  if (!sameEntry(active.entry, resolved.entry)) {
    throw new AppError("CONFLICT", "ACTIVE_RELEASE_ENTRY_MISMATCH");
  }
  return active;
}
