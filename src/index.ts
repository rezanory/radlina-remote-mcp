import { pathToFileURL } from "node:url";

import { armPendingHealthGate, prepareReleaseBoot } from "./admin/release-state.js";

async function main(): Promise<void> {
  const selected = await prepareReleaseBoot();
  if (selected.pending) armPendingHealthGate(selected.manifest);

  if (!selected.entry) {
    const local = await import("./app-entry.js");
    await local.runApp();
    return;
  }
  const release = (await import(pathToFileURL(selected.entry).href)) as { runApp?: unknown };
  if (typeof release.runApp !== "function") throw new Error("INVALID_RELEASE_ENTRY_EXPORT");
  await (release.runApp as () => Promise<void>)();
}

void main().catch((error: unknown) => {
  console.error(
    "[server] startup failed",
    error instanceof Error ? error.message : "unknown error",
  );
  process.exitCode = 1;
});
