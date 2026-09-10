import { rename, writeFile } from "node:fs/promises";
import path from "node:path";

import { stringify as stringifyYaml } from "yaml";

import type { AppConfig } from "../config/schema.js";

const OWNER_ENV = [
  "PATH",
  "SYSTEMROOT",
  "SYSTEMDRIVE",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "LOCALAPPDATA",
  "APPDATA",
  "PROGRAMDATA",
  "PROGRAMFILES",
  "COMSPEC",
  "PATHEXT",
  "WINDIR",
  "USERNAME",
  "USERDOMAIN",
  "NUMBER_OF_PROCESSORS",
  "PROCESSOR_ARCHITECTURE",
];

export function trustedOwnerConfig(input: AppConfig): AppConfig {
  const config = structuredClone(input);
  const profile = config.profiles[config.policy.defaultProfile];
  if (!profile) throw new Error("default profile is missing");
  profile.roots = ["C:\\"];
  profile.allowShell = true;
  profile.allowTrash = true;
  profile.envAllowlist = [...new Set([...profile.envAllowlist, ...OWNER_ENV])];
  config.server.requestBodyBytes = 10 * 1024 * 1024;
  config.server.requestTimeoutMs = 120_000;
  config.policy.maxConcurrentRequests = 128;
  config.policy.rateLimitPerMinute = 10_000;

  config.policy.maxFileBytes = 1024 * 1024 * 1024;
  config.policy.maxOutputBytes = 100 * 1024 * 1024;
  config.policy.maxProcessRuntimeMs = 24 * 60 * 60 * 1000;
  config.policy.maxSearchRuntimeMs = 60 * 60 * 1000;
  config.policy.maxSessions = 256;
  return config;
}

export async function persistTrustedOwnerConfig(
  configFile: string,
  current: AppConfig,
): Promise<{
  profile: string;
  roots: string[];
  allowShell: boolean;
  allowTrash: boolean;
  restartRequired: true;
}> {
  const next = trustedOwnerConfig(current);
  const directory = path.dirname(configFile);
  const temp = path.join(directory, `.local.yaml.${process.pid}.${Date.now()}.tmp`);
  await writeFile(temp, stringifyYaml(next), { encoding: "utf8", mode: 0o600, flag: "wx" });
  await rename(temp, configFile);
  const selected = next.profiles[next.policy.defaultProfile]!;
  return {
    profile: next.policy.defaultProfile,
    roots: selected.roots,
    allowShell: selected.allowShell,
    allowTrash: selected.allowTrash,
    restartRequired: true,
  };
}
