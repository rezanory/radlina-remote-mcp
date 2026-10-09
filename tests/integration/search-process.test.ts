import { execFileSync } from "node:child_process";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { Store } from "../../src/persistence/store.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import { FilesystemService } from "../../src/tools/filesystem/service.js";
import { ProcessManager } from "../../src/tools/process/manager.js";
import { SearchManager } from "../../src/tools/search/manager.js";
import { testConfig } from "../helpers/config.js";

const cleanup: string[] = [];

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function waitFor(read: () => { status: string }): Promise<{ status: string }> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const value = read();
    if (value.status !== "running") return value;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("session did not complete before timeout");
}

describe("reconnectable jobs", () => {
  it("persists paged ripgrep results", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-search-"));
    cleanup.push(root);
    await writeFile(path.join(root, "one.txt"), "needle\n", "utf8");
    const config = testConfig(root);
    config.dependencies.ripgrepExecutable =
      "C:\\radlina-remote-mcp\\.runtime\\ripgrep-15.2.0-x86_64-pc-windows-msvc\\rg.exe";
    const store = new Store(config.storage.directory);
    const searches = new SearchManager(config, store);
    const files = new FilesystemService([root], 1024 * 1024, path.join(root, ".trash"), false);
    const started = (await searches.start("subject", "test", files.resolver, {
      mode: "content",
      path: root,
      pattern: "needle",
      literal: true,
      maxResults: 10,
    })) as { searchId: string };
    await waitFor(() => searches.status(started.searchId, "subject") as { status: string });
    const result = (await searches.results(started.searchId, "subject")) as { results: unknown[] };
    expect(result.results).toHaveLength(1);
    store.close();
  });

  it("persists process output for reconnectable reads", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-process-"));
    cleanup.push(root);
    const config = testConfig(root);
    const profile = config.profiles["test"];
    if (!profile) throw new Error("test profile missing");
    profile.commands = [{ executable: process.execPath, argumentPatterns: ["^--version$"] }];
    const store = new Store(config.storage.directory);
    const policy = new PolicyEngine(config, {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    });
    const processes = new ProcessManager(config, store, policy);
    const files = new FilesystemService([root], 1024 * 1024, path.join(root, ".trash"), false);
    const started = (await processes.start("subject", "test", profile, files.resolver, {
      executable: process.execPath,
      args: ["--version"],
      cwd: root,
    })) as { sessionId: string };
    await waitFor(() => {
      const row = store.db
        .prepare("SELECT status FROM process_sessions WHERE id=?")
        .get(started.sessionId) as {
        status: string;
      };
      return row;
    });
    const result = (await processes.readOutput(started.sessionId, "subject")) as { output: string };
    expect(result.output).toContain(process.version);
    store.close();
  });

  it("keeps a long job alive within its runtime cap and supports terminal polling", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-process-long-job-"));
    cleanup.push(root);
    const config = testConfig(root);
    const profile = config.profiles["test"];
    if (!profile) throw new Error("test profile missing");
    profile.commands = [{ executable: process.execPath, argumentPatterns: [".*"] }];
    const store = new Store(config.storage.directory);
    const policy = new PolicyEngine(config, {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    });
    const processes = new ProcessManager(config, store, policy);
    const files = new FilesystemService([root], 1024 * 1024, path.join(root, ".trash"), false);
    const started = (await processes.start("subject", "test", profile, files.resolver, {
      executable: process.execPath,
      args: ["-e", "setTimeout(() => process.stdout.write('LONG_JOB_DONE\\n'), 1200)"],
      cwd: root,
      timeoutMs: 5_000,
    })) as { sessionId: string; status: string; outputCursor: string };

    expect(started.status).toBe("running");
    try {
      let cursor: string | undefined = started.outputCursor;
      let result = (await processes.readOutput(started.sessionId, "subject", cursor)) as {
        status: string;
        output: string;
        nextCursor: string;
        hasMore: boolean;
        exitCode: number | null;
      };
      let collectedOutput = result.output;
      const deadline = Date.now() + 7_000;
      while (result.status === "running" || result.hasMore) {
        if (Date.now() >= deadline) throw new Error("long process did not reach a terminal state");
        cursor = result.nextCursor;
        await new Promise((resolve) => setTimeout(resolve, 25));
        result = (await processes.readOutput(
          started.sessionId,
          "subject",
          cursor,
        )) as typeof result;
        collectedOutput += result.output;
      }

      expect(result.status).toBe("complete");
      expect(result.exitCode).toBe(0);
      expect(collectedOutput).toContain("LONG_JOB_DONE");
    } finally {
      processes.shutdown();
      store.close();
    }
  });

  it("enforces process timeouts and bounded output", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-process-limits-"));
    cleanup.push(root);
    const config = testConfig(root);
    config.policy.maxProcessRuntimeMs = 2_000;
    config.policy.maxOutputBytes = 4096;
    const profile = config.profiles["test"];
    if (!profile) throw new Error("test profile missing");
    profile.commands = [{ executable: process.execPath, argumentPatterns: [".*"] }];
    const store = new Store(config.storage.directory);
    const policy = new PolicyEngine(config, {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    });
    const processes = new ProcessManager(config, store, policy);
    const files = new FilesystemService([root], 1024 * 1024, path.join(root, ".trash"), false);

    const timed = (await processes.start("subject", "test", profile, files.resolver, {
      executable: process.execPath,
      args: ["-e", "setInterval(() => {}, 1000)"],
      cwd: root,
      timeoutMs: 100,
    })) as { sessionId: string };
    const timedStatus = await waitFor(
      () =>
        store.db.prepare("SELECT status FROM process_sessions WHERE id=?").get(timed.sessionId) as {
          status: string;
        },
    );
    expect(timedStatus.status).toBe("timed-out");

    const noisy = (await processes.start("subject", "test", profile, files.resolver, {
      executable: process.execPath,
      args: ["-e", "process.stdout.write('x'.repeat(200000));setInterval(() => {}, 1000)"],
      cwd: root,
    })) as { sessionId: string };
    const noisyStatus = await waitFor(
      () =>
        store.db.prepare("SELECT status FROM process_sessions WHERE id=?").get(noisy.sessionId) as {
          status: string;
        },
    );
    expect(noisyStatus.status).toBe("output-limit");
    const output = (await processes.readOutput(noisy.sessionId, "subject", undefined, 8192)) as {
      bytesRead: number;
    };
    expect(output.bytesRead).toBeLessThanOrEqual(config.policy.maxOutputBytes);
    const row = store.db
      .prepare("SELECT output_path FROM process_sessions WHERE id=?")
      .get(noisy.sessionId) as { output_path: string };
    expect((await stat(row.output_path)).size).toBeLessThanOrEqual(config.policy.maxOutputBytes);
    store.close();
  });

  it("does not write to a closed store when child finalization races shutdown", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-process-shutdown-"));
    cleanup.push(root);
    const config = testConfig(root);
    const profile = config.profiles["test"];
    if (!profile) throw new Error("test profile missing");
    profile.commands = [{ executable: process.execPath, argumentPatterns: [".*"] }];
    const store = new Store(config.storage.directory);
    const policy = new PolicyEngine(config, {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    });
    const processes = new ProcessManager(config, store, policy);
    const files = new FilesystemService([root], 1024 * 1024, path.join(root, ".trash"), false);
    await processes.start("subject", "test", profile, files.resolver, {
      executable: process.execPath,
      args: ["-e", "setTimeout(() => {}, 250)"],
      cwd: root,
    });
    store.close();
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(store.isOpen()).toBe(false);
  });

  it("reconciles orphaned process rows after restart", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-process-reconcile-"));
    cleanup.push(root);
    const config = testConfig(root);
    const store = new Store(config.storage.directory);
    const policy = new PolicyEngine(config, {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    });
    store.db
      .prepare(
        "INSERT INTO process_sessions(id,subject,profile,pid,executable,args_json,output_path,status,started_at,start_identity) VALUES(?,?,?,?,?,?,?,?,?,?)",
      )
      .run(
        "orphan",
        "subject",
        "test",
        2_147_483_647,
        process.execPath,
        "{}",
        path.join(root, "orphan.log"),
        "running",
        Date.now(),
        "impossible",
      );
    const processes = new ProcessManager(config, store, policy);
    await processes.reconcile();
    const row = store.db.prepare("SELECT status FROM process_sessions WHERE id='orphan'").get() as {
      status: string;
    };
    expect(row.status).toBe("interrupted");
    store.close();
  });

  it("does not overwrite a cancelled search during its close race", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "radlina-search-cancel-"));
    cleanup.push(root);
    for (let index = 0; index < 100; index += 1) {
      await writeFile(path.join(root, `file-${index}.txt`), `needle ${index}\n`, "utf8");
    }
    const config = testConfig(root);
    config.dependencies.ripgrepExecutable =
      "C:\\radlina-remote-mcp\\.runtime\\ripgrep-15.2.0-x86_64-pc-windows-msvc\\rg.exe";
    const store = new Store(config.storage.directory);
    const searches = new SearchManager(config, store);
    const files = new FilesystemService([root], 1024 * 1024, path.join(root, ".trash"), false);
    const started = (await searches.start("subject", "test", files.resolver, {
      mode: "content",
      path: root,
      pattern: "needle",
      literal: true,
      maxResults: 10_000,
    })) as { searchId: string };
    searches.cancel(started.searchId, "subject");
    await new Promise((resolve) => setTimeout(resolve, 250));
    const status = searches.status(started.searchId, "subject") as { status: string };
    expect(status.status).toBe("cancelled");
    store.close();
  });
});

describe("trusted-owner direct executable parity", () => {
  const windowsTest = process.platform === "win32" ? it : it.skip;

  windowsTest(
    "executes Git, Node, Python, PowerShell, cmd, npm, and npx with commands empty",
    async () => {
      const root = await mkdtemp(path.join(os.tmpdir(), "radlina-owner-process-"));
      cleanup.push(root);
      const locate = (name: string): string =>
        execFileSync("where.exe", [name], { encoding: "utf8", windowsHide: true })
          .split(/\r?\n/u)
          .find(Boolean)!;
      const config = testConfig(root);
      config.policy.maxSessions = 16;
      const profile = config.profiles["test"]!;
      profile.roots = ["C:\\"];
      profile.commands = [];
      profile.allowShell = true;
      profile.envAllowlist = ["PATH", "SYSTEMROOT", "COMSPEC"];
      const store = new Store(config.storage.directory);
      try {
        const policy = new PolicyEngine(config, {
          killSwitch: () => false,
          emergencyReadOnly: () => false,
        });
        const processes = new ProcessManager(config, store, policy);
        const files = new FilesystemService(
          profile.roots,
          1024 * 1024,
          path.join(root, ".trash"),
          false,
        );
        const cases = [
          {
            name: "git",
            executable: "C:\\Program Files\\Git\\cmd\\git.exe",
            args: ["--version"],
            marker: "git version",
          },
          {
            name: "node",
            executable: process.execPath,
            args: ["--version"],
            marker: process.version,
          },
          {
            name: "python",
            executable: locate("python.exe"),
            args: ["--version"],
            marker: "Python",
          },
          {
            name: "powershell",
            executable: locate("powershell.exe"),
            args: ["-NoProfile", "-NonInteractive", "-Command", "Write-Output RADLINA_PS_PASS"],
            marker: "RADLINA_PS_PASS",
          },
          {
            name: "cmd",
            executable: locate("cmd.exe"),
            args: ["/d", "/s", "/c", "echo RADLINA_CMD_PASS"],
            marker: "RADLINA_CMD_PASS",
          },
          {
            name: "npm",
            executable: locate("cmd.exe"),
            args: ["/d", "/s", "/c", "call npm.cmd --version"],
            marker: ".",
          },
          {
            name: "npx",
            executable: locate("cmd.exe"),
            args: ["/d", "/s", "/c", "call npx.cmd --version"],
            marker: ".",
          },
        ];
        for (const selected of cases) {
          const started = (await processes.start("subject", "test", profile, files.resolver, {
            executable: selected.executable,
            args: selected.args,
            cwd: root,
          })) as { sessionId: string };
          await waitFor(
            () =>
              store.db
                .prepare("SELECT status FROM process_sessions WHERE id=?")
                .get(started.sessionId) as { status: string },
          );
          const result = (await processes.readOutput(started.sessionId, "subject")) as {
            output: string;
            exitCode: number | null;
          };
          expect(result.exitCode, `${selected.name}: ${result.output}`).toBe(0);
          expect(result.output, selected.name).toContain(selected.marker);
        }
      } finally {
        store.close();
      }
    },
    30_000,
  );
});
