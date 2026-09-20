import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { resolveWindowsExecutable } from "../../src/utils/windows-executable.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("resolveWindowsExecutable", () => {
  it("resolves an extensionless absolute shim to its PATHEXT companion", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "radlina-executable-"));
    temporaryDirectories.push(directory);
    const shim = path.join(directory, "npm");
    const command = `${shim}.CMD`;
    await writeFile(command, "@echo off\r\n", "utf8");

    await expect(resolveWindowsExecutable(shim, { pathExtValue: ".CMD" })).resolves.toBe(
      path.win32.normalize(command),
    );
  });

  it("prefers PATHEXT companions over an extensionless POSIX shim on PATH", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "radlina-executable-"));
    temporaryDirectories.push(directory);
    await writeFile(path.join(directory, "npm"), "#!/usr/bin/env bash\n", "utf8");
    const command = path.join(directory, "npm.CMD");
    await writeFile(command, "@echo off\r\n", "utf8");

    await expect(
      resolveWindowsExecutable("npm", { pathValue: directory, pathExtValue: ".CMD" }),
    ).resolves.toBe(path.win32.normalize(command));
  });
});
