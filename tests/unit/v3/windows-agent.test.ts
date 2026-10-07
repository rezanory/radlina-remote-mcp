import type { AuthInfo } from "@modelcontextprotocol/server";
import { describe, expect, it, vi } from "vitest";

import type { WorkspaceProfile } from "../../../src/config/schema.js";
import { CapabilityRegistry } from "../../../src/components/registry.js";
import { PolicyEngine } from "../../../src/policy/engine.js";
import { canonicalJson, sha256 } from "../../../src/utils/json.js";
import { HmacDistributedAuditSigner } from "../../../src/v3/audit/distributed.js";
import { V3CapabilityRuntime } from "../../../src/v3/capability/runtime.js";
import { V3ExecutionPolicyGuard } from "../../../src/v3/security/policy.js";
import {
  WindowsDeviceAgent,
  createWindowsPlatformAdapter,
  type WindowsAdapterBindings,
} from "../../../src/v3/device/windows-agent.js";
import { assertPlatformAdapterConformance } from "../../../src/v3/platform/contracts.js";
import type { FilesystemService } from "../../../src/tools/filesystem/service.js";
import type { ProcessManager } from "../../../src/tools/process/manager.js";
import type { SearchManager } from "../../../src/tools/search/manager.js";
import { testConfig } from "../../helpers/config.js";

const profile: WorkspaceProfile = {
  roots: ["C:\\"],
  commands: [],
  allowShell: true,
  allowTrash: false,
  envAllowlist: [],
};

function fakeBindings(): WindowsAdapterBindings {
  const filesystem = {
    resolver: {},
    getFileInfo: vi.fn(async () => ({
      path: "C:\\test.txt",
      type: "file",
      size: 4,
      modifiedAt: "2026-10-07T18:00:00.000Z",
    })),
    readFile: vi.fn(async () => ({ content: "test", encoding: "utf8" })),
    writeFile: vi.fn(async () => ({ ok: true })),
    listDirectory: vi.fn(async () => ({
      entries: [{ name: "a.txt" }, { name: "b.txt" }],
    })),
  } as unknown as FilesystemService;

  const processes = {
    start: vi.fn(async () => ({ sessionId: "p1", pid: 42 })),
    readOutput: vi.fn(async () => ({
      status: "complete",
      exitCode: 0,
      nextCursor: "cursor",
    })),
    interact: vi.fn(() => ({ acceptedBytes: 1 })),
    terminate: vi.fn(async () => ({ terminated: true })),
  } as unknown as ProcessManager;

  const searches = {
    start: vi.fn(async () => ({ searchId: "s1" })),
    status: vi.fn(() => ({ status: "complete", resultCount: 2 })),
    results: vi.fn(async () => ({ results: [{ path: "a" }, { path: "b" }] })),
    cancel: vi.fn(() => ({ cancelled: true })),
  } as unknown as SearchManager;

  return {
    subject: "owner",
    profileName: "test",
    profile,
    filesystem,
    processes,
    searches,
    agentVersion: "3.0.0-alpha.1",
    readiness: async () => ({ ready: true }),
    scheduleRestart: async () => undefined,
  };
}

describe("V3 Windows agent", () => {
  it("conforms to the platform-neutral adapter contract and exposes Windows identity", async () => {
    const adapter = createWindowsPlatformAdapter(fakeBindings());
    const info = await assertPlatformAdapterConformance(adapter);
    expect(info.platform).toBe("windows");
    expect(info.agentVersion).toBe("3.0.0-alpha.1");
    expect(info.health).toBe("healthy");
  });

  it("maps V2 filesystem, process and search services through the Windows adapter", async () => {
    const bindings = fakeBindings();
    const adapter = createWindowsPlatformAdapter(bindings);

    await expect(adapter.filesystem.getFileInfo("C:\\test.txt")).resolves.toEqual({
      path: "C:\\test.txt",
      kind: "file",
      size: 4,
      modifiedAt: "2026-10-07T18:00:00.000Z",
    });
    await expect(adapter.filesystem.readFile("C:\\test.txt", 0, 4)).resolves.toEqual(
      Buffer.from("test"),
    );
    await expect(adapter.filesystem.listDirectory("C:\\")).resolves.toEqual(["a.txt", "b.txt"]);

    await expect(
      adapter.process.start({
        executable: "cmd.exe",
        args: ["/c", "exit", "0"],
        cwd: "C:\\",
      }),
    ).resolves.toEqual({ sessionId: "p1", pid: 42 });
    await expect(adapter.process.read("p1")).resolves.toMatchObject({
      status: "complete",
      exitCode: 0,
    });

    await expect(
      adapter.search.start({
        root: "C:\\",
        pattern: "test",
        mode: "content",
        caseSensitive: false,
        literal: true,
        maxResults: 10,
      }),
    ).resolves.toEqual({ searchId: "s1" });
    await expect(adapter.search.results("s1")).resolves.toHaveLength(2);
  });

  it("round-trips bytes through the real Windows DPAPI secret protector", async () => {
    if (process.platform !== "win32") return;
    const adapter = createWindowsPlatformAdapter(fakeBindings());
    const plaintext = Buffer.from("radlina-windows-agent-secret");
    const protectedValue = await adapter.secrets.protect(plaintext);
    expect(Buffer.from(protectedValue).equals(plaintext)).toBe(false);
    const restored = await adapter.secrets.unprotect(protectedValue);
    expect(Buffer.from(restored)).toEqual(plaintext);
  });

  it("binds hello and capability execution to the enrolled Windows device identity", async () => {
    const bindings = fakeBindings();
    const adapter = createWindowsPlatformAdapter(bindings);
    const registry = new CapabilityRegistry();
    registry.register({
      id: "radlina.device",
      version: "3.0.0",
      description: "Windows agent test",
      capabilities: [
        {
          id: "device.health",
          version: "1.0.0",
          description: "health",
          requiredScope: "device:read",
          risk: "low",
          readOnly: true,
          idempotent: true,
          execute: async () => ({ status: "healthy" }),
        },
      ],
    });

    const config = testConfig("C:\\");
    const policy = new V3ExecutionPolicyGuard(
      new PolicyEngine(config, {
        killSwitch: () => false,
        emergencyReadOnly: () => false,
      }),
    );
    const runtime = new V3CapabilityRuntime(
      registry,
      policy,
      { record: async () => "c".repeat(64) },
      new HmacDistributedAuditSigner(Buffer.alloc(32, 5)),
      () => "2026-10-07T18:00:00+03:00",
    );
    const agent = new WindowsDeviceAgent(adapter, registry, runtime, {
      deviceId: "windows-main",
      tags: ["primary"],
      trustState: "trusted",
      identity: {
        deviceId: "windows-main",
        agentInstanceId: "1505db46-56df-4c32-a221-a28863b41228",
        agentVersion: "3.0.0-alpha.1",
        publicKeyFingerprint: "a".repeat(64),
        enrolledAt: "2026-10-07T18:00:00+03:00",
      },
    });

    await expect(agent.hello()).resolves.toMatchObject({
      descriptor: {
        deviceId: "windows-main",
        platform: "windows",
        trustState: "trusted",
        capabilities: ["device.health"],
      },
    });

    const input = {};
    const auth: AuthInfo = {
      token: "token",
      clientId: "client",
      scopes: ["device:read"],
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    };
    const outcome = await agent.execute(
      {
        requestId: "fe26ef06-9156-4c95-b523-bda7e1ad77a1",
        workflowExecutionId: "wf-1",
        nodeId: "health",
        attempt: 1,
        targetDeviceId: "windows-main",
        capability: "device.health",
        input,
        inputSha256: sha256(canonicalJson(input)),
        timeoutMs: 5_000,
        globalCorrelationId: "corr-1",
        traceId: "trace-1",
      },
      {
        auth,
        subject: "owner",
        profile: "test",
        isCancelled: () => false,
      },
    );
    expect(outcome).toMatchObject({
      ok: true,
      result: { status: "healthy" },
      receipt: {
        resolvedDeviceId: "windows-main",
        terminalState: "completed",
      },
    });
  });
});
