import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const outputIndex = process.argv.indexOf("--output");
if (outputIndex < 0 || !process.argv[outputIndex + 1]) {
  throw new Error("--output <new-evidence-directory> is required");
}
const outputRoot = path.resolve(process.argv[outputIndex + 1]);
const exists = await stat(outputRoot)
  .then(() => true)
  .catch(() => false);
if (exists) throw new Error(`evidence directory already exists: ${outputRoot}`);
await mkdir(outputRoot, { recursive: true });

function sanitize(value) {
  return value
    .replace(/Bearer\s+[A-Za-z0-9._~+/-]+=*/giu, "Bearer [REDACTED]")
    .replace(/(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{16,}/giu, "[REDACTED]")
    .replace(
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/giu,
      "[REDACTED PRIVATE KEY]",
    );
}

function sha(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function command(executable, args) {
  try {
    const result = await execute(executable, args, {
      cwd: projectRoot,
      windowsHide: true,
      timeout: 10 * 60_000,
      maxBuffer: 32 * 1024 * 1024,
      env: { ...process.env, CI: "true" },
    });
    return { exitCode: 0, output: `${result.stdout}${result.stderr}` };
  } catch (error) {
    return {
      exitCode: Number.isInteger(error.code) ? error.code : 1,
      output: `${error.stdout ?? ""}${error.stderr ?? ""}\n${error.message ?? "command failed"}`,
    };
  }
}

async function git(...args) {
  const result = await command("git.exe", args);
  if (result.exitCode !== 0) throw new Error(result.output);
  return result.output.trim();
}

const initialStatus = await git("status", "--porcelain=v1");
if (initialStatus) throw new Error("closure validation requires a clean source worktree");
const source = {
  gitSha: await git("rev-parse", "HEAD"),
  gitTree: await git("rev-parse", "HEAD^{tree}"),
  branch: await git("branch", "--show-current"),
};
const node = "C:\\radlina-remote-mcp\\.runtime\\node-v24.20.0-win-x64\\node.exe";
const npmCli =
  "C:\\radlina-remote-mcp\\.runtime\\node-v24.20.0-win-x64\\node_modules\\npm\\bin\\npm-cli.js";
const npm = (...args) => ({ executable: node, args: [npmCli, ...args] });
const gates = [
  { name: "clean-install", ...npm("ci", "--ignore-scripts") },
  { name: "format", ...npm("run", "format:check") },
  { name: "lint", ...npm("run", "lint") },
  { name: "typecheck", ...npm("run", "typecheck") },
  { name: "unit", ...npm("run", "test:unit") },
  { name: "integration", ...npm("run", "test:integration") },
  { name: "security", ...npm("run", "test:security") },
  { name: "resilience", ...npm("run", "test:resilience") },
  { name: "full", ...npm("test") },
  { name: "build", ...npm("run", "build") },
  { name: "dependency-audit", ...npm("run", "security:audit") },
  {
    name: "builder-syntax",
    executable: node,
    args: ["--check", "scripts/operations/build-release.mjs"],
  },
  {
    name: "drill-syntax",
    executable: node,
    args: ["--check", "scripts/operations/isolated-upgrade-drill.mjs"],
  },
  {
    name: "verifier-syntax",
    executable: node,
    args: ["--check", "scripts/operations/verify-release.mjs"],
  },
  {
    name: "secret-scan",
    executable: "powershell.exe",
    args: [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      path.join(projectRoot, "scripts", "operations", "security-scan.ps1"),
    ],
  },
  { name: "git-diff-check", executable: "git.exe", args: ["diff", "--check", "HEAD"] },
];

const records = [];
for (const gate of gates) {
  const startedAt = new Date().toISOString();
  const started = performance.now();
  const result = await command(gate.executable, gate.args);
  const output = sanitize(result.output);
  const logName = `${String(records.length + 1).padStart(2, "0")}-${gate.name}.log`;
  await writeFile(path.join(outputRoot, logName), output, "utf8");
  records.push({
    name: gate.name,
    executable: gate.executable,
    args: gate.args,
    startedAt,
    durationMs: Math.round(performance.now() - started),
    exitCode: result.exitCode,
    output: logName,
    outputSha256: sha(output),
  });
  process.stdout.write(`${gate.name} exit=${result.exitCode}\n`);
}

const finalStatus = await git("status", "--porcelain=v1");
const finalSource = {
  gitSha: await git("rev-parse", "HEAD"),
  gitTree: await git("rev-parse", "HEAD^{tree}"),
  branch: await git("branch", "--show-current"),
};
const failed = records.filter((record) => record.exitCode !== 0).map((record) => record.name);
if (finalStatus) failed.push("source-worktree-clean-after-validation");
if (JSON.stringify(source) !== JSON.stringify(finalSource)) failed.push("source-identity-stable");
const receipt = {
  schema: "radlina.closure-validation.v1",
  generatedAt: new Date().toISOString(),
  status: failed.length === 0 ? "PASS" : "FAIL",
  source,
  finalSource,
  sourceWorktreeClean: !finalStatus,
  node: execFileURL(node),
  gates: records,
  failed,
};
const receiptPath = path.join(outputRoot, "VALIDATION_RECEIPT.json");
await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
if (failed.length > 0) throw new Error(`closure validation failed: ${failed.join(", ")}`);
process.stdout.write(`${JSON.stringify({ status: "PASS", receiptPath, source })}\n`);

function execFileURL(executable) {
  return path.resolve(executable);
}
