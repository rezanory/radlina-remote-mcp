import { readFile } from "node:fs/promises";
import path from "node:path";

import { parse as parseYaml } from "yaml";

import { configSchema, type AppConfig } from "./schema.js";

const PROJECT_ROOT = "C:\\radlina-remote-mcp";

export function configPath(): string {
  return process.env["RADLINA_CONFIG"] ?? path.join(PROJECT_ROOT, "config", "local.yaml");
}

export async function loadConfig(explicitPath?: string): Promise<AppConfig> {
  const selected = explicitPath ?? configPath();
  const fallback = path.join(PROJECT_ROOT, "config", "example.yaml");
  let raw: string;
  try {
    raw = await readFile(selected, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT" || explicitPath) throw error;
    raw = await readFile(fallback, "utf8");
  }
  const parsed: unknown = parseYaml(raw);
  if (process.env["RADLINA_PUBLIC_URL"] && typeof parsed === "object" && parsed !== null) {
    const root = parsed as Record<string, unknown>;
    if (typeof root["server"] === "object" && root["server"] !== null) {
      (root["server"] as Record<string, unknown>)["publicUrl"] = process.env["RADLINA_PUBLIC_URL"];
    }
  }
  if (typeof parsed === "object" && parsed !== null) {
    const root = parsed as Record<string, unknown>;
    if (typeof root["auth"] === "object" && root["auth"] !== null) {
      const auth = root["auth"] as Record<string, unknown>;
      if (process.env["RADLINA_EXTERNAL_ISSUER"])
        auth["externalIssuer"] = process.env["RADLINA_EXTERNAL_ISSUER"];
      if (process.env["RADLINA_EXTERNAL_JWKS_URL"])
        auth["externalJwksUrl"] = process.env["RADLINA_EXTERNAL_JWKS_URL"];
    }
  }
  return configSchema.parse(parsed);
}

export function validateConfig(
  input: unknown,
): { valid: true; config: AppConfig } | { valid: false; issues: unknown } {
  const result = configSchema.safeParse(input);
  return result.success
    ? { valid: true, config: result.data }
    : { valid: false, issues: result.error.issues };
}
