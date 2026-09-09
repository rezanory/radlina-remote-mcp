import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const projectRoot = "C:\\radlina-remote-mcp";
const lock = JSON.parse(await readFile(path.join(projectRoot, "package-lock.json"), "utf8"));
const packages = Object.entries(lock.packages ?? {})
  .filter(([location]) => location.startsWith("node_modules/"))
  .map(([location, metadata]) => ({
    name: location.slice("node_modules/".length),
    version: metadata.version ?? "unknown",
    license: metadata.license ?? "UNKNOWN",
  }))
  .sort((left, right) => left.name.localeCompare(right.name));
const outputDirectory = path.join(projectRoot, "reports", "PH-01");
await mkdir(outputDirectory, { recursive: true });
await writeFile(
  path.join(outputDirectory, "licenses.json"),
  `${JSON.stringify({ generatedAt: new Date().toISOString(), packages }, undefined, 2)}\n`,
  "utf8",
);
console.log(`wrote ${packages.length} package license records`);
