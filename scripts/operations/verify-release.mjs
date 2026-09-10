import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const [candidate, manifest] = process.argv.slice(2);
if (!candidate || !manifest) {
  throw new Error("usage: verify-release.mjs <candidate-directory> <manifest-sha256>");
}
const verifier = await import(
  pathToFileURL(path.join(projectRoot, "dist", "src", "admin", "release-manifest.js")).href
);
const result = await verifier.verifyReleaseRoot(path.resolve(candidate), manifest.toLowerCase());
process.stdout.write(
  `${JSON.stringify({
    status: "PASS",
    manifest: result.manifestId,
    version: result.manifest.version,
    entry: result.manifest.entry,
    source: result.manifest.source,
    evidence: result.manifest.evidence,
    files: result.manifest.files.length,
  })}\n`,
);
