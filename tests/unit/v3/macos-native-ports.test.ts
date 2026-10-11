import { mkdtemp, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  createMacOSNativePorts,
  type MacOSNativePorts,
} from "../../../src/v3/device/macos-native-ports.js";

describe("V3 macOS native ports", () => {
  let root: string;
  let ports: MacOSNativePorts;

  beforeEach(async () => {
    root = await realpath(await mkdtemp(path.join(tmpdir(), "radlina-macos-native-")));
    ports = await createMacOSNativePorts({
      roots: [root],
      executableAllowlist: ["/bin/sh"],
      environmentAllowlist: ["PATH"],
      ripgrepExecutable: "/usr/local/bin/rg",
      maxProcessRuntimeMs: 5_000,
      maxSearchRuntimeMs: 5_000,
    });
  });

  afterEach(async () => {
    await ports.close();
    await rm(root, { recursive: true, force: true });
  });

  it("bounds filesystem access to configured real paths", async () => {
    const marker = path.join(root, "marker.txt");
    await ports.filesystem.writeFile(marker, Buffer.from("radlina"), false);

    await expect(ports.filesystem.readFile(marker, 0, 32)).resolves.toEqual(Buffer.from("radlina"));
    await expect(ports.filesystem.listDirectory(root)).resolves.toContain("marker.txt");
    await expect(ports.filesystem.readFile("/etc/hosts", 0, 32)).rejects.toThrow(
      /outside the configured macOS roots/u,
    );

    const link = path.join(root, "hosts-link");
    await symlink("/etc/hosts", link);
    await expect(ports.filesystem.writeFile(link, Buffer.from("blocked"), true)).rejects.toThrow(
      /symbolic link/u,
    );
  });

  it("executes only allowlisted programs and supports termination", async () => {
    const completed = await ports.process.start({
      executable: "/bin/sh",
      args: ["-c", "exit 0"],
      cwd: root,
    });
    let snapshot = await ports.process.read(completed.sessionId);
    for (let attempt = 0; attempt < 100 && snapshot.status === "running"; attempt += 1) {
      await delay(10);
      snapshot = await ports.process.read(completed.sessionId);
    }
    expect(snapshot).toMatchObject({ status: "complete", exitCode: 0 });

    await expect(
      ports.process.start({ executable: "/usr/bin/true", args: [], cwd: root }),
    ).rejects.toThrow(/not allowlisted/u);

    const running = await ports.process.start({
      executable: "/bin/sh",
      args: ["-c", "sleep 5"],
      cwd: root,
    });
    await ports.process.terminate(running.sessionId, true);
    await expect(ports.process.read(running.sessionId)).resolves.toMatchObject({
      status: "terminated",
    });
  });

  it("uses real ripgrep for bounded file and content search", async () => {
    const marker = path.join(root, "radlina-marker.txt");
    await ports.filesystem.writeFile(marker, Buffer.from("native-content-marker\n"), false);

    const files = await ports.search.start({
      root,
      pattern: "radlina-marker",
      mode: "files",
      caseSensitive: true,
      literal: true,
      maxResults: 10,
    });
    await waitForSearch(ports, files.searchId);
    await expect(ports.search.results(files.searchId)).resolves.toEqual([{ path: marker }]);

    const content = await ports.search.start({
      root,
      pattern: "native-content-marker",
      mode: "content",
      caseSensitive: true,
      literal: true,
      maxResults: 10,
    });
    await waitForSearch(ports, content.searchId);
    await expect(ports.search.results(content.searchId)).resolves.toEqual([
      { path: marker, line: 1, text: "native-content-marker" },
    ]);
  });
});

async function waitForSearch(ports: MacOSNativePorts, searchId: string): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const snapshot = await ports.search.status(searchId);
    if (snapshot.status !== "running" && snapshot.status !== "queued") {
      expect(snapshot.status).toBe("complete");
      return;
    }
    await delay(10);
  }
  throw new Error("search did not finish");
}
