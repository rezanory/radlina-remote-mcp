import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { AppError } from "../../src/errors.js";
import { FilesystemService } from "../../src/tools/filesystem/service.js";
import { SafePathResolver } from "../../src/tools/filesystem/safe-path.js";

const cleanup: string[] = [];

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function temporaryRoot(prefix: string): Promise<string> {
  const result = await mkdtemp(path.join(os.tmpdir(), prefix));
  cleanup.push(result);
  return result;
}

describe("SafePathResolver", () => {
  it("accepts contained paths and rejects traversal, ADS, UNC, and device names", async () => {
    const root = await temporaryRoot("radlina-root-");
    await writeFile(path.join(root, "ok.txt"), "ok");
    const resolver = new SafePathResolver([root]);
    const resolvedContainedPath = await resolver.resolve("ok.txt", { mustExist: true });
    expect(path.win32.normalize(resolvedContainedPath).toLowerCase()).toBe(
      path.win32.normalize(path.join(root, "ok.txt")).toLowerCase(),
    );
    await expect(resolver.resolve("..\\escape.txt", { mustExist: false })).rejects.toMatchObject({
      code: "INVALID_PATH",
    });
    await expect(resolver.resolve("ok.txt:secret", { mustExist: false })).rejects.toMatchObject({
      code: "INVALID_PATH",
    });
    await expect(
      resolver.resolve("\\\\server\\share\\file", { mustExist: false }),
    ).rejects.toMatchObject({ code: "INVALID_PATH" });
    await expect(resolver.resolve("CON", { mustExist: false })).rejects.toMatchObject({
      code: "INVALID_PATH",
    });
  });

  it("rejects junction escapes and nested links in directory copies", async () => {
    const root = await temporaryRoot("radlina-root-");
    const outside = await temporaryRoot("radlina-outside-");
    await mkdir(path.join(root, "source"));
    await writeFile(path.join(outside, "secret.txt"), "secret");
    const junction = path.join(root, "source", "outside");
    try {
      await symlink(outside, junction, "junction");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    const resolver = new SafePathResolver([root]);
    await expect(
      resolver.resolve(path.join(junction, "secret.txt"), { mustExist: true }),
    ).rejects.toBeInstanceOf(AppError);
    const files = new FilesystemService([root], 1024 * 1024, path.join(root, ".trash"), false);
    await expect(
      files.copy(path.join(root, "source"), path.join(root, "copy"), false),
    ).rejects.toMatchObject({ code: "INVALID_PATH" });
  });

  it("writes atomically and replays exact-match edits", async () => {
    const root = await temporaryRoot("radlina-root-");
    const files = new FilesystemService([root], 1024 * 1024, path.join(root, ".trash"), false);
    await expect(files.writeFile("sample.txt", "before", "utf8", false)).resolves.toMatchObject({
      bytes: 6,
    });
    await expect(files.editBlock("sample.txt", "before", "after")).resolves.toMatchObject({
      replacements: 1,
    });
    await expect(files.writeFile("sample.txt", "again", "utf8", true)).resolves.toMatchObject({
      bytes: 5,
    });
    const read = (await files.readFile("sample.txt")) as { content: string };
    expect(read.content).toBe("again");
  });
});
