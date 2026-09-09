import path from "node:path";
import { stat } from "node:fs/promises";

import { AuditChain } from "./audit/chain.js";
import { AuthService } from "./auth/service.js";
import { loadConfig } from "./config/index.js";
import type { AppConfig } from "./config/schema.js";
import { Store } from "./persistence/store.js";
import { PolicyEngine } from "./policy/engine.js";
import { ToolRuntime } from "./policy/runtime.js";
import { FilesystemService } from "./tools/filesystem/service.js";
import { ProcessManager } from "./tools/process/manager.js";
import { SearchManager } from "./tools/search/manager.js";

export type AppRuntime = {
  config: AppConfig;
  store: Store;
  audit: AuditChain;
  auth: AuthService;
  policy: PolicyEngine;
  tools: ToolRuntime;
  filesystems: Map<string, FilesystemService>;
  searches: SearchManager;
  processes: ProcessManager;
  startedAt: number;
};

export async function createRuntime(
  explicitConfigPath?: string,
  options: { reconcileSessions?: boolean } = {},
): Promise<AppRuntime> {
  const config = await loadConfig(explicitConfigPath);
  const ripgrep = await stat(config.dependencies.ripgrepExecutable);
  if (!ripgrep.isFile()) throw new Error("configured ripgrep executable is not a regular file");
  const store = new Store(config.storage.directory);
  const audit = new AuditChain(config, store);
  await audit.initialize();
  const policy = new PolicyEngine(config, {
    killSwitch: () =>
      (store.get("control:killSwitch") ?? String(config.policy.killSwitch)) === "true",
    emergencyReadOnly: () =>
      (store.get("control:emergencyReadOnly") ?? String(config.policy.emergencyReadOnly)) ===
      "true",
  });
  const auth = new AuthService(config, store);
  await auth.initialize();
  const filesystems = new Map<string, FilesystemService>();
  for (const [name, profile] of Object.entries(config.profiles)) {
    filesystems.set(
      name,
      new FilesystemService(
        profile.roots,
        config.policy.maxFileBytes,
        path.join(config.storage.directory, "trash", name),
        profile.allowTrash,
      ),
    );
  }
  const searches = new SearchManager(config, store);
  const processes = new ProcessManager(config, store, policy);
  if (options.reconcileSessions !== false) {
    searches.reconcile();
    await processes.reconcile();
  }
  return {
    config,
    store,
    audit,
    auth,
    policy,
    tools: new ToolRuntime(policy, audit, store),
    filesystems,
    searches,
    processes,
    startedAt: Date.now(),
  };
}

export function closeRuntime(runtime: AppRuntime): void {
  runtime.store.close();
}
