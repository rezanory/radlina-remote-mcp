import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { copyFile, lstat, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const manifestSchema = "radlina.release-manifest.v2";
const reserved = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

function fail(message) {
  throw new Error(message);
}

function argumentsForBuild(values) {
  let output;
  const evidence = [];
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === "--output") output = values[++index];
    else if (value === "--evidence") evidence.push(values[++index]);
    else fail(`unknown or incomplete argument: ${value}`);
  }
  if (!output || evidence.length < 1) fail("--output and at least one --evidence are required");
  return { output: path.resolve(output), evidence: evidence.map((item) => path.resolve(item)) };
}

function git(...args) {
  return execFileSync("git", args, {
    cwd: projectRoot,
    windowsHide: true,
    encoding: "utf8",
  }).trim();
}

function validateRelative(value) {
  if (
    !value ||
    value.includes("\\") ||
    value.includes("\0") ||
    path.posix.isAbsolute(value) ||
    path.win32.isAbsolute(value)
  ) {
    fail(`invalid release path: ${value}`);
  }
  for (const part of value.split("/")) {
    if (
      !part ||
      part === "." ||
      part === ".." ||
      /[<>:"|?*]/u.test(part) ||
      [...part].some((character) => character.charCodeAt(0) <= 31) ||
      /[. ]$/u.test(part) ||
      reserved.test(part)
    ) {
      fail(`invalid release path: ${value}`);
    }
  }
  return value;
}

async function hashFile(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

async function collectTree(root, current = "") {
  const directory = current ? path.join(root, ...current.split("/")) : root;
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink()) fail(`release input contains a reparse point: ${entry.name}`);
    const relative = validateRelative(current ? `${current}/${entry.name}` : entry.name);
    if (entry.isDirectory()) files.push(...(await collectTree(root, relative)));
    else if (entry.isFile()) files.push(relative);
    else fail(`release input is not a regular file: ${relative}`);
  }
  return files.sort();
}

async function addFile(source, relative, selected, folded) {
  const normalized = validateRelative(relative);
  const key = normalized.toLowerCase();
  if (folded.has(key)) fail(`case-insensitive duplicate release path: ${normalized}`);
  const info = await lstat(source);
  if (!info.isFile() || info.isSymbolicLink()) fail(`release input is not regular: ${source}`);
  folded.add(key);
  selected.push({ source, relative: normalized });
}

async function addTree(sourceRoot, targetRoot, selected, folded) {
  for (const relative of await collectTree(sourceRoot)) {
    await addFile(
      path.join(sourceRoot, ...relative.split("/")),
      `${targetRoot}/${relative}`,
      selected,
      folded,
    );
  }
}

const args = argumentsForBuild(process.argv.slice(2));
if (git("status", "--porcelain")) fail("release build requires a clean source worktree");
const outputExists = await stat(args.output)
  .then(() => true)
  .catch(() => false);
if (outputExists) fail(`release output already exists: ${args.output}`);

const source = {
  gitSha: git("rev-parse", "HEAD").toLowerCase(),
  gitTree: git("rev-parse", "HEAD^{tree}").toLowerCase(),
  branch: git("branch", "--show-current"),
};
if (!/^[0-9a-f]{40}$/u.test(source.gitSha) || !/^[0-9a-f]{40}$/u.test(source.gitTree)) {
  fail("invalid Git source identity");
}
if (!source.branch) fail("detached source is not eligible for release packaging");

const packageValue = JSON.parse(await readFile(path.join(projectRoot, "package.json"), "utf8"));
if (typeof packageValue.version !== "string" || !packageValue.version)
  fail("package version missing");

const selected = [];
const folded = new Set();
await addTree(path.join(projectRoot, "dist", "src"), "dist/src", selected, folded);
await addTree(
  path.join(projectRoot, "scripts", "operations"),
  "scripts/operations",
  selected,
  folded,
);
for (const relative of [
  "package.json",
  "package-lock.json",
  "service/RadlinaRemoteMCP.xml",
  "config/example.yaml",
]) {
  await addFile(path.join(projectRoot, ...relative.split("/")), relative, selected, folded);
}

const evidence = [];
const evidenceNames = new Set();
for (const sourceFile of args.evidence) {
  const name = validateRelative(path.basename(sourceFile));
  const foldedName = name.toLowerCase();
  if (evidenceNames.has(foldedName)) fail(`duplicate evidence name: ${name}`);
  evidenceNames.add(foldedName);
  const info = await stat(sourceFile);
  if (!info.isFile()) fail(`evidence is not a regular file: ${sourceFile}`);
  const sha256 = await hashFile(sourceFile);
  evidence.push({ name, bytes: info.size, sha256 });
  await addFile(sourceFile, `evidence/${name}`, selected, folded);
}

selected.sort((left, right) => (left.relative < right.relative ? -1 : 1));
await mkdir(args.output, { recursive: false });
const files = [];
for (const item of selected) {
  const target = path.join(args.output, ...item.relative.split("/"));
  await mkdir(path.dirname(target), { recursive: true });
  await copyFile(item.source, target);
  const info = await stat(target);
  files.push({ path: item.relative, bytes: info.size, sha256: await hashFile(target) });
}

const manifest = {
  schema: manifestSchema,
  version: packageValue.version,
  entry: "dist/src/app-entry.js",
  source,
  evidence,
  files,
};
const raw = `${JSON.stringify(manifest, null, 2)}\n`;
const manifestId = createHash("sha256").update(raw).digest("hex");
await writeFile(path.join(args.output, "RELEASE_MANIFEST.json"), raw, {
  encoding: "utf8",
  flag: "wx",
});

const verifier = await import(
  pathToFileURL(path.join(projectRoot, "dist", "src", "admin", "release-manifest.js")).href
);
const verified = await verifier.verifyReleaseRoot(args.output, manifestId);
if (verified.manifestId !== manifestId) fail("post-build manifest identity mismatch");
process.stdout.write(
  `${JSON.stringify({
    status: "PASS",
    output: args.output,
    manifest: manifestId,
    version: manifest.version,
    source,
    evidence,
    files: files.length,
  })}\n`,
);
