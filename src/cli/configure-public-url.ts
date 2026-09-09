import { randomUUID } from "node:crypto";
import { copyFile, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

import { configPath, validateConfig } from "../config/index.js";

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

async function main(): Promise<void> {
  const rawUrl = process.argv[2];
  if (!rawUrl) throw new Error("usage: configure-public-url <https-url>");
  const publicUrl = new URL(rawUrl);
  if (
    publicUrl.protocol !== "https:" ||
    publicUrl.username ||
    publicUrl.password ||
    publicUrl.search ||
    publicUrl.hash
  ) {
    throw new Error("public URL must be an HTTPS origin without credentials, query, or fragment");
  }
  publicUrl.pathname = "/";
  const target = configPath();
  await mkdir(path.dirname(target), { recursive: true });
  try {
    await readFile(target, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    await copyFile(path.join("C:\\radlina-remote-mcp", "config", "example.yaml"), target);
  }
  const parsed = parseYaml(await readFile(target, "utf8")) as Record<string, unknown>;
  const server = parsed["server"] as Record<string, unknown>;
  server["publicUrl"] = publicUrl.origin;
  server["allowedHosts"] = Array.from(
    new Set([...stringArray(server["allowedHosts"]), publicUrl.hostname]),
  );
  server["allowedOrigins"] = Array.from(
    new Set([
      ...stringArray(server["allowedOrigins"]),
      "chatgpt.com",
      "chat.openai.com",
      "openai.com",
    ]),
  );
  const validation = validateConfig(parsed);
  if (!validation.valid)
    throw new Error(`updated configuration is invalid: ${JSON.stringify(validation.issues)}`);
  const temporary = `${target}.${randomUUID()}.tmp`;
  await writeFile(temporary, stringifyYaml(validation.config), {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  try {
    await rename(temporary, target);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
  console.log(`public URL configured: ${publicUrl.origin}`);
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "configuration update failed");
  process.exitCode = 1;
});
