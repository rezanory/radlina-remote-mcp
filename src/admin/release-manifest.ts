import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readdir, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";

import { AppError } from "../errors.js";

export const RELEASE_MANIFEST_FILE = "RELEASE_MANIFEST.json";
export const RELEASE_MANIFEST_SCHEMA = "radlina.release-manifest.v2";
export const MANIFEST_ID = /^[0-9a-f]{64}$/;
const GIT_OBJECT_ID = /^[0-9a-f]{40}$/;
const FILE_HASH = /^[0-9a-f]{64}$/;
const WINDOWS_RESERVED = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

export type ReleaseFile = { path: string; bytes: number; sha256: string };
export type ReleaseEvidence = { name: string; bytes: number; sha256: string };
export type ReleaseManifest = {
  schema: typeof RELEASE_MANIFEST_SCHEMA;
  version: string;
  entry: string;
  source: { gitSha: string; gitTree: string; branch: string };
  evidence: ReleaseEvidence[];
  files: ReleaseFile[];
};

function fail(code: string, message = code): never {
  throw new AppError("INVALID_INPUT", message, { code });
}

function exactKeys(value: Record<string, unknown>, keys: string[], code: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((item, index) => item !== expected[index])) {
    fail(code);
  }
}

export function normalizeManifestId(value: string): string {
  const normalized = value.toLowerCase();
  if (!MANIFEST_ID.test(normalized)) fail("INVALID_RELEASE_MANIFEST_ID");
  return normalized;
}

export function validateReleaseRelativePath(value: string): string {
  if (
    value.length < 1 ||
    value.length > 32_000 ||
    value.includes("\\") ||
    value.includes("\0") ||
    path.posix.isAbsolute(value) ||
    path.win32.isAbsolute(value)
  ) {
    fail("INVALID_RELEASE_PATH");
  }
  const parts = value.split("/");
  for (const part of parts) {
    if (
      !part ||
      part === "." ||
      part === ".." ||
      /[<>:"|?*]/u.test(part) ||
      [...part].some((character) => character.charCodeAt(0) <= 31) ||
      /[. ]$/u.test(part) ||
      WINDOWS_RESERVED.test(part)
    ) {
      fail("INVALID_RELEASE_PATH");
    }
  }
  return parts.join("/");
}

export function releasePath(root: string, relative: string): string {
  return path.join(root, ...validateReleaseRelativePath(relative).split("/"));
}

export function parseReleaseManifest(raw: string): ReleaseManifest {
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    fail("INVALID_RELEASE_MANIFEST_JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_RELEASE_MANIFEST");
  }
  const manifest = value as Record<string, unknown>;
  exactKeys(
    manifest,
    ["schema", "version", "entry", "source", "evidence", "files"],
    "INVALID_RELEASE_MANIFEST",
  );
  if (
    manifest["schema"] !== RELEASE_MANIFEST_SCHEMA ||
    typeof manifest["version"] !== "string" ||
    manifest["version"].length < 1 ||
    manifest["version"].length > 128 ||
    typeof manifest["entry"] !== "string" ||
    !manifest["source"] ||
    typeof manifest["source"] !== "object" ||
    Array.isArray(manifest["source"]) ||
    !Array.isArray(manifest["evidence"]) ||
    manifest["evidence"].length < 1 ||
    manifest["evidence"].length > 1_000 ||
    !Array.isArray(manifest["files"]) ||
    manifest["files"].length < 1 ||
    manifest["files"].length > 20_000
  ) {
    fail("INVALID_RELEASE_MANIFEST");
  }

  const source = manifest["source"] as Record<string, unknown>;
  exactKeys(source, ["gitSha", "gitTree", "branch"], "INVALID_RELEASE_SOURCE");
  if (
    typeof source["gitSha"] !== "string" ||
    !GIT_OBJECT_ID.test(source["gitSha"]) ||
    typeof source["gitTree"] !== "string" ||
    !GIT_OBJECT_ID.test(source["gitTree"]) ||
    typeof source["branch"] !== "string" ||
    source["branch"].length < 1 ||
    source["branch"].length > 512
  ) {
    fail("INVALID_RELEASE_SOURCE");
  }

  for (const evidenceValue of manifest["evidence"]) {
    if (!evidenceValue || typeof evidenceValue !== "object" || Array.isArray(evidenceValue)) {
      fail("INVALID_RELEASE_EVIDENCE");
    }
    const evidence = evidenceValue as Record<string, unknown>;
    exactKeys(evidence, ["name", "bytes", "sha256"], "INVALID_RELEASE_EVIDENCE");
    if (
      typeof evidence["name"] !== "string" ||
      evidence["name"].length < 1 ||
      evidence["name"].length > 256 ||
      !Number.isSafeInteger(evidence["bytes"]) ||
      (evidence["bytes"] as number) < 0 ||
      typeof evidence["sha256"] !== "string" ||
      !FILE_HASH.test(evidence["sha256"])
    ) {
      fail("INVALID_RELEASE_EVIDENCE");
    }
  }

  const seen = new Set<string>();
  let previous = "";
  for (const fileValue of manifest["files"]) {
    if (!fileValue || typeof fileValue !== "object" || Array.isArray(fileValue)) {
      fail("INVALID_RELEASE_FILE");
    }
    const file = fileValue as Record<string, unknown>;
    exactKeys(file, ["path", "bytes", "sha256"], "INVALID_RELEASE_FILE");
    if (
      typeof file["path"] !== "string" ||
      !Number.isSafeInteger(file["bytes"]) ||
      (file["bytes"] as number) < 0 ||
      typeof file["sha256"] !== "string" ||
      !FILE_HASH.test(file["sha256"])
    ) {
      fail("INVALID_RELEASE_FILE");
    }
    const selected = validateReleaseRelativePath(file["path"]);
    const folded = selected.toLowerCase();
    if (seen.has(folded)) fail("DUPLICATE_RELEASE_FILE_CASE_INSENSITIVE");
    if (previous && previous >= selected) fail("UNSORTED_RELEASE_FILES");
    seen.add(folded);
    previous = selected;
  }
  const entry = validateReleaseRelativePath(manifest["entry"]);
  if (!seen.has(entry.toLowerCase())) fail("RELEASE_ENTRY_NOT_MANIFEST_BOUND");
  return manifest as unknown as ReleaseManifest;
}

async function sha256File(file: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

async function regularFileWithin(root: string, relative: string): Promise<string> {
  const normalized = validateReleaseRelativePath(relative);
  const rootReal = await realpath(root);
  let selected = root;
  const parts = normalized.split("/");
  for (let index = 0; index < parts.length; index += 1) {
    selected = path.join(selected, parts[index]!);
    const info = await lstat(selected);
    if (info.isSymbolicLink()) fail("RELEASE_REPARSE_POINT");
    if (index === parts.length - 1) {
      if (!info.isFile()) fail("RELEASE_NONFILE");
    } else if (!info.isDirectory()) {
      fail("RELEASE_PATH_ANCESTOR_NOT_DIRECTORY");
    }
  }
  const selectedReal = await realpath(selected);
  const prefix = rootReal.endsWith(path.sep) ? rootReal : `${rootReal}${path.sep}`;
  if (!selectedReal.toLowerCase().startsWith(prefix.toLowerCase())) fail("RELEASE_PATH_ESCAPE");
  return selected;
}

async function enumerateReleaseFiles(root: string, current = ""): Promise<string[]> {
  const directory = current ? releasePath(root, current) : root;
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink()) fail("RELEASE_REPARSE_POINT");
    const relative = current ? `${current}/${entry.name}` : entry.name;
    validateReleaseRelativePath(relative);
    if (entry.isDirectory()) {
      files.push(...(await enumerateReleaseFiles(root, relative)));
    } else if (entry.isFile()) {
      files.push(relative);
    } else {
      fail("RELEASE_NONFILE");
    }
  }
  return files.sort();
}

export async function verifyReleaseRoot(
  root: string,
  expectedManifest: string,
): Promise<{ manifest: ReleaseManifest; manifestId: string; entryFile: string }> {
  const manifestId = normalizeManifestId(expectedManifest);
  const rootInfo = await lstat(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) fail("INVALID_RELEASE_ROOT");
  const manifestFile = await regularFileWithin(root, RELEASE_MANIFEST_FILE);
  const raw = await readFile(manifestFile, "utf8");
  const actualManifest = createHash("sha256").update(raw).digest("hex");
  if (actualManifest !== manifestId) fail("RELEASE_MANIFEST_HASH_MISMATCH");
  const manifest = parseReleaseManifest(raw);

  const expectedFiles = [RELEASE_MANIFEST_FILE, ...manifest.files.map((file) => file.path)].sort();
  const actualFiles = await enumerateReleaseFiles(root);
  if (
    expectedFiles.length !== actualFiles.length ||
    expectedFiles.some((file, index) => file !== actualFiles[index])
  ) {
    fail("RELEASE_FILE_SET_MISMATCH");
  }

  for (const file of manifest.files) {
    const selected = await regularFileWithin(root, file.path);
    const info = await stat(selected);
    if (info.size !== file.bytes) fail("RELEASE_FILE_SIZE_MISMATCH");
    if ((await sha256File(selected)) !== file.sha256) {
      fail("RELEASE_FILE_HASH_MISMATCH");
    }
  }
  const entryFile = await regularFileWithin(root, manifest.entry);
  return { manifest, manifestId, entryFile };
}
