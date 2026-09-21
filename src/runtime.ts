import path from "node:path";
import { stat } from "node:fs/promises";

import { UpgradeManager } from "./admin/upgrade.js";
import { AuditChain } from "./audit/chain.js";
import { AuthService } from "./auth/service.js";
import { createBuiltinComponents } from "./components/builtin.js";
import { CapabilityRegistry } from "./components/registry.js";
import { configPath, loadConfig } from "./config/index.js";
import type { AppConfig } from "./config/schema.js";
import { OperatorManager } from "./operator/manager.js";
import { Store } from "./persistence/store.js";
import { PolicyEngine } from "./policy/engine.js";
import { ToolRuntime } from "./policy/runtime.js";
import { ReliabilitySupervisor } from "./reliability/supervisor.js";
import { FilesystemService } from "./tools/filesystem/service.js";
import { ProcessManager } from "./tools/process/manager.js";
import { SearchManager } from "./tools/search/manager.js";

export type AppRuntime = {
  config: AppConfig;
  configFile: string;
  store: Store;
  audit: AuditChain;
  auth: AuthService;
  policy: PolicyEngine;
  tools: ToolRuntime;
  filesystems: Map<string, FilesystemService>;
  searches: SearchManager;
  processes: ProcessManager;
  upgrades: UpgradeManager;
  components: CapabilityRegistry;
  operator: OperatorManager;
  reliability: ReliabilitySupervisor;
  startedAt: number;
};

export async function createRuntime(
  explicitConfigPath?: string,
  options: { reconcileSessions?: boolean } = {},
): Promise<AppRuntime> {
  const startedAt = Date.now();
  const config = await loadConfig(explicitConfigPath);
  const configFile = explicitConfigPath ?? configPath();
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
  const upgrades = new UpgradeManager(
    config,
    configFile,
    UpgradeManager.productionRestart(configFile),
  );
  const components = new CapabilityRegistry();
  for (const component of createBuiltinComponents({
    config,
    filesystems,
    processes,
    startedAt,
  })) {
    components.register(component);
  }
  components.register({
    id: "radlina.operator",
    version: "2.0.0",
    description: "Durable deterministic Smart Operator orchestration engine.",
    capabilities: [],
  });
  const operator = new OperatorManager(store, policy, components);
  const reliability = new ReliabilitySupervisor(config, store, audit, auth, searches, processes);
  if (options.reconcileSessions !== false) {
    searches.reconcile();
    await processes.reconcile();
    operator.reconcile();
  }
  await reliability.start(options.reconcileSessions !== false);
  return {
    config,
    configFile,
    store,
    audit,
    auth,
    policy,
    tools: new ToolRuntime(policy, audit, store),
    filesystems,
    searches,
    processes,
    upgrades,
    components,
    operator,
    reliability,
    startedAt,
  };
}

export async function closeRuntime(runtime: AppRuntime): Promise<void> {
  runtime.reliability.stop();
  await runtime.operator.shutdown();
  await Promise.all([runtime.searches.shutdown(), runtime.processes.shutdown()]);
  runtime.store.close();
}
