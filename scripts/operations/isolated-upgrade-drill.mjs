import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, stat, unlink, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { stringify as stringifyYaml } from "yaml";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const tempParent = path.join(projectRoot, ".temp");

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!["--candidate", "--manifest", "--output"].includes(name) || !value) {
      throw new Error(`invalid argument: ${name ?? "missing"}`);
    }
    result[name.slice(2)] = value;
  }
  if (!result.candidate || !result.manifest || !result.output) {
    throw new Error("--candidate, --manifest, and --output are required");
  }
  return {
    candidate: path.resolve(result.candidate),
    manifest: result.manifest.toLowerCase(),
    output: path.resolve(result.output),
  };
}

function sha(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("port allocation failed");
  await new Promise((resolve) => server.close(resolve));
  return address.port;
}

async function waitForExit(child, timeoutMs) {
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("child exit timeout"));
    }, timeoutMs);
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function runBoot(configFile, base, expectHealthy) {
  const child = spawn(process.execPath, [path.join(projectRoot, "dist", "src", "index.js")], {
    cwd: projectRoot,
    env: { ...process.env, RADLINA_CONFIG: configFile },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    output += chunk;
  });
  child.stderr.on("data", (chunk) => {
    output += chunk;
  });
  if (!expectHealthy) {
    const exitCode = await waitForExit(child, 15_000);
    if (exitCode === 0) throw new Error(`broken release exited cleanly: ${output}`);
    return { status: "EXPECTED_FAILURE", exitCode, output: output.slice(-4_000) };
  }
  let ready = false;
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (child.exitCode !== null) break;
    if (output.includes("[server] listening")) {
      ready = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  if (!ready) {
    child.kill();
    await waitForExit(child, 5_000).catch(() => undefined);
    throw new Error(`isolated release did not become ready: ${output}`);
  }
  const authProbe = await fetch(`${base}/mcp`, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(5_000),
  });
  if (authProbe.status !== 401) {
    throw new Error(`isolated auth boundary failed: ${authProbe.status}`);
  }
  await new Promise((resolve) => setTimeout(resolve, 200));
  child.kill("SIGTERM");
  const exitCode = await waitForExit(child, 10_000);
  return { status: "HEALTHY", exitCode, output: output.slice(-4_000) };
}

async function brokenCandidate(source, destination) {
  await cp(source, destination, { recursive: true, errorOnExist: true, force: false });
  const manifestFile = path.join(destination, "RELEASE_MANIFEST.json");
  const manifest = JSON.parse(await readFile(manifestFile, "utf8"));
  const body = "export async function runApp(){throw new Error('INTENTIONAL_BROKEN_RELEASE')}\n";
  const entryFile = path.join(destination, ...manifest.entry.split("/"));
  await writeFile(entryFile, body, "utf8");
  const entry = manifest.files.find((item) => item.path === manifest.entry);
  if (!entry) throw new Error("release entry missing from manifest");
  entry.bytes = Buffer.byteLength(body);
  entry.sha256 = sha(body);
  const raw = `${JSON.stringify(manifest, null, 2)}\n`;
  await writeFile(manifestFile, raw, "utf8");
  return sha(raw);
}

const args = parseArgs(process.argv.slice(2));
await mkdir(tempParent, { recursive: true });
const root = await mkdtemp(path.join(tempParent, "isolated-upgrade-"));
const receipt = {
  schema: "radlina.self-contained-upgrade-evidence.v1",
  timestampUtc: new Date().toISOString(),
  status: "FAIL",
  finalManifest: args.manifest,
  rdcRequired: false,
  runnerRequired: false,
  externalShellRequired: false,
  trustedOwnerMode: true,
  rollbackVerified: false,
  rePromotionVerified: false,
  automaticRollbackVerified: false,
  unknownMutationNoReplayVerified: false,
  duplicateReplayVerified: false,
  concurrentMutationRejected: false,
  negativeManifestValidation: {},
  boots: [],
};

try {
  const modules = pathToFileURL(path.join(projectRoot, "dist", "src"));
  const [
    { UpgradeManager },
    releaseState,
    manifestApi,
    { Store },
    { AuditChain },
    { PolicyEngine },
    { ToolRuntime },
    jsonApi,
  ] = await Promise.all([
    import(new URL("./admin/upgrade.js", `${modules.href}/`).href),
    import(new URL("./admin/release-state.js", `${modules.href}/`).href),
    import(new URL("./admin/release-manifest.js", `${modules.href}/`).href),
    import(new URL("./persistence/store.js", `${modules.href}/`).href),
    import(new URL("./audit/chain.js", `${modules.href}/`).href),
    import(new URL("./policy/engine.js", `${modules.href}/`).href),
    import(new URL("./policy/runtime.js", `${modules.href}/`).href),
    import(new URL("./utils/json.js", `${modules.href}/`).href),
  ]);
  await manifestApi.verifyReleaseRoot(args.candidate, args.manifest);
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const configFile = path.join(root, "config", "local.yaml");
  const state = path.join(root, ".state");
  const config = {
    server: {
      host: "127.0.0.1",
      port,
      publicUrl: base,
      allowedHosts: ["127.0.0.1", "localhost"],
      allowedOrigins: [],
      requestBodyBytes: 10 * 1024 * 1024,
      requestTimeoutMs: 120_000,
    },
    auth: {
      mode: "internal",
      accessTokenTtlSeconds: 600,
      refreshTokenTtlSeconds: 86_400,
      pairingCodeTtlSeconds: 600,
      allowedRedirectHosts: ["127.0.0.1", "localhost"],
    },
    policy: {
      defaultProfile: "radlina",
      emergencyReadOnly: false,
      killSwitch: false,
      maxConcurrentRequests: 128,
      rateLimitPerMinute: 10_000,
      maxFileBytes: 1024 * 1024 * 1024,
      maxOutputBytes: 100 * 1024 * 1024,
      maxProcessRuntimeMs: 86_400_000,
      maxSearchRuntimeMs: 3_600_000,
      maxSessions: 256,
    },
    dependencies: {
      ripgrepExecutable:
        "C:\\radlina-remote-mcp\\.runtime\\ripgrep-15.2.0-x86_64-pc-windows-msvc\\rg.exe",
    },
    profiles: {
      radlina: {
        roots: ["C:\\"],
        commands: [],
        allowShell: true,
        allowTrash: true,
        envAllowlist: ["PATH", "SYSTEMROOT", "TEMP", "TMP", "COMSPEC"],
      },
    },
    storage: { directory: state },
    audit: {
      directory: path.join(state, "audit"),
      rotateBytes: 5_242_880,
      userRedactionPatterns: [],
    },
  };
  await mkdir(path.dirname(configFile), { recursive: true });
  await mkdir(path.join(root, "service"), { recursive: true });
  await writeFile(configFile, stringifyYaml(config), "utf8");
  await writeFile(path.join(root, "service", "RadlinaRemoteMCP.exe"), "isolated-wrapper", "utf8");
  process.env.RADLINA_CONFIG = configFile;
  delete process.env.RADLINA_ACTIVE_RELEASE_MANIFEST;
  const manager = new UpgradeManager(config, configFile, () => undefined);

  await manager.stage(args.candidate, args.manifest);
  await manager.preflight(args.manifest);
  await manager.activate(args.manifest);
  receipt.boots.push(await runBoot(configFile, base, true));
  let active = await releaseState.readActiveRelease();
  if (active?.manifest !== args.manifest || active.pending) throw new Error("A activation failed");

  await manager.rollback();
  receipt.boots.push(await runBoot(configFile, base, true));
  active = await releaseState.readActiveRelease();
  if (active?.manifest !== releaseState.ROOT_RELEASE || active.pending) {
    throw new Error("ROOT rollback failed");
  }
  receipt.rollbackVerified = true;

  await manager.activate(args.manifest);
  receipt.boots.push(await runBoot(configFile, base, true));
  active = await releaseState.readActiveRelease();
  if (active?.manifest !== args.manifest || active.pending)
    throw new Error("A re-promotion failed");
  receipt.rePromotionVerified = true;

  const brokenRoot = path.join(root, "broken-release");
  const brokenManifest = await brokenCandidate(args.candidate, brokenRoot);
  await manager.stage(brokenRoot, brokenManifest);
  await manager.preflight(brokenManifest);
  await manager.activate(brokenManifest);
  receipt.boots.push(await runBoot(configFile, base, false));
  receipt.boots.push(await runBoot(configFile, base, true));
  active = await releaseState.readActiveRelease();
  if (active?.manifest !== args.manifest || active.pending) {
    throw new Error("automatic rollback did not recover A");
  }
  receipt.automaticRollbackVerified = true;

  const store = new Store(config.storage.directory);
  try {
    const audit = new AuditChain(config, store);
    await audit.initialize();
    const policy = new PolicyEngine(config, {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    });
    const tools = new ToolRuntime(policy, audit, store);
    const auth = {
      token: "isolated",
      clientId: "isolated-drill",
      scopes: ["admin"],
      expiresAt: Math.floor(Date.now() / 1000) + 600,
      extra: { sub: "isolated-drill" },
    };
    let duplicateExecutions = 0;
    const duplicateKey = randomUUID();
    const invoke = () =>
      tools.run({
        auth,
        tool: "admin_activate_release",
        scope: "admin",
        args: { manifest: args.manifest },
        idempotencyKey: duplicateKey,
        handler: async () => {
          duplicateExecutions += 1;
          return await manager.activate(args.manifest);
        },
      });
    const first = await invoke();
    const second = await invoke();
    if (
      first.isError ||
      second.isError ||
      duplicateExecutions !== 1 ||
      second.structuredContent?.replayed !== true
    ) {
      throw new Error("duplicate idempotency replay failed");
    }
    receipt.duplicateReplayVerified = true;

    const unknownKey = randomUUID();
    const unknownArgs = { manifest: args.manifest };
    const argsHash = jsonApi.sha256(jsonApi.canonicalJson(unknownArgs));
    if (!store.claimIdempotency(unknownKey, "isolated-drill", "admin_activate_release", argsHash)) {
      throw new Error("unknown claim setup failed");
    }
    let unknownExecutions = 0;
    const unknown = await tools.run({
      auth,
      tool: "admin_activate_release",
      scope: "admin",
      args: unknownArgs,
      idempotencyKey: unknownKey,
      handler: async () => {
        unknownExecutions += 1;
        return await manager.activate(args.manifest);
      },
    });
    if (!unknown.isError || unknownExecutions !== 0) throw new Error("unknown mutation replayed");
    receipt.unknownMutationNoReplayVerified = true;
    const auditResult = await audit.verify(await audit.files());
    if (!auditResult.valid) throw new Error("isolated audit chain invalid");
  } finally {
    store.close();
  }

  await writeFile(
    releaseState.mutationLockPath(),
    `${JSON.stringify({
      schema: "radlina.upgrade-lock.v1",
      token: "isolated-live-lock",
      pid: process.pid,
      operation: "isolated-concurrency-check",
      acquiredAt: new Date().toISOString(),
      acquiredAtMs: Date.now(),
    })}\n`,
    "utf8",
  );
  try {
    await manager.activate(args.manifest);
    throw new Error("concurrent mutation was not rejected");
  } catch (error) {
    if (!String(error).includes("UPGRADE_IN_PROGRESS")) throw error;
    receipt.concurrentMutationRejected = true;
  } finally {
    await unlink(releaseState.mutationLockPath()).catch(() => undefined);
  }

  await manifestApi.verifyReleaseRoot(args.candidate, args.manifest);
  await manifestApi
    .verifyReleaseRoot(args.candidate, "0".repeat(64))
    .then(() => {
      throw new Error("stale manifest accepted");
    })
    .catch((error) => {
      if (!String(error).includes("RELEASE_MANIFEST_HASH_MISMATCH")) throw error;
      receipt.negativeManifestValidation.staleManifest = "PASS";
    });
  const wrongRoot = path.join(root, "wrong-hash-release");
  await cp(args.candidate, wrongRoot, { recursive: true });
  const wrongManifest = JSON.parse(
    await readFile(path.join(wrongRoot, "RELEASE_MANIFEST.json"), "utf8"),
  );
  await writeFile(path.join(wrongRoot, ...wrongManifest.entry.split("/")), "tampered", "utf8");
  await manifestApi
    .verifyReleaseRoot(wrongRoot, args.manifest)
    .then(() => {
      throw new Error("wrong file hash accepted");
    })
    .catch((error) => {
      if (!/RELEASE_FILE_(SIZE|HASH)_MISMATCH/u.test(String(error))) throw error;
      receipt.negativeManifestValidation.wrongHash = "PASS";
    });
  const unsafe = JSON.parse(
    await readFile(path.join(args.candidate, "RELEASE_MANIFEST.json"), "utf8"),
  );
  unsafe.files[0].path = "../escape.js";
  try {
    manifestApi.parseReleaseManifest(`${JSON.stringify(unsafe)}\n`);
    throw new Error("path escape accepted");
  } catch (error) {
    if (!String(error).includes("INVALID_RELEASE_PATH")) throw error;
    receipt.negativeManifestValidation.pathEscape = "PASS";
  }

  const junctionRoot = path.join(root, "junction-release");
  await cp(args.candidate, junctionRoot, { recursive: true });
  const junctionTarget = path.join(root, "junction-target");
  await mkdir(junctionTarget);
  const junction = path.join(junctionRoot, "junction-extra");
  execFileSync("cmd.exe", ["/d", "/c", "mklink", "/J", junction, junctionTarget], {
    windowsHide: true,
    stdio: "ignore",
  });
  await manifestApi
    .verifyReleaseRoot(junctionRoot, args.manifest)
    .then(() => {
      throw new Error("junction accepted");
    })
    .catch((error) => {
      if (!String(error).includes("RELEASE_REPARSE_POINT")) throw error;
      receipt.negativeManifestValidation.junction = "PASS";
    });

  receipt.status = "PASS";
} finally {
  delete process.env.RADLINA_CONFIG;
  delete process.env.RADLINA_ACTIVE_RELEASE_MANIFEST;
  await mkdir(path.dirname(args.output), { recursive: true });
  await writeFile(args.output, `${JSON.stringify(receipt, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
  await rm(root, { recursive: true, force: true });
}

if (receipt.status !== "PASS") throw new Error(`isolated drill failed; see ${args.output}`);
process.stdout.write(
  `${JSON.stringify({ status: "PASS", output: args.output, manifest: args.manifest })}\n`,
);
