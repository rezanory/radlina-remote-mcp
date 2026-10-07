import type { AuthInfo } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";

import { CapabilityRegistry } from "../../../src/components/registry.js";
import { PolicyEngine } from "../../../src/policy/engine.js";
import { canonicalJson, sha256 } from "../../../src/utils/json.js";
import { HmacDistributedAuditSigner } from "../../../src/v3/audit/distributed.js";
import { V3CapabilityRuntime } from "../../../src/v3/capability/runtime.js";
import {
  MacOSDeviceAgent,
  MacOSKeychainSecretProtector,
  createMacOSPlatformAdapter,
  type SecurityCommandRunner,
} from "../../../src/v3/device/macos-agent.js";
import type {
  FilesystemPort,
  ProcessPort,
  SearchPort,
} from "../../../src/v3/platform/contracts.js";
import { assertPlatformAdapterConformance } from "../../../src/v3/platform/contracts.js";
import { V3ExecutionPolicyGuard } from "../../../src/v3/security/policy.js";
import { testConfig } from "../../helpers/config.js";

function fakePorts() {
  const filesystem: FilesystemPort = {
    getFileInfo: async (path) => ({
      path,
      kind: "file",
      size: 4,
      modifiedAt: "2026-10-08T00:00:00Z",
    }),
    readFile: async () => Buffer.from("test"),
    writeFile: async () => undefined,
    listDirectory: async () => ["a.txt", "b.txt"],
  };
  const process: ProcessPort = {
    start: async () => ({ sessionId: "p1", pid: 42 }),
    read: async (sessionId) => ({ sessionId, status: "complete", exitCode: 0 }),
    interact: async () => undefined,
    terminate: async () => undefined,
  };
  const search: SearchPort = {
    start: async () => ({ searchId: "s1" }),
    status: async (searchId) => ({ searchId, status: "complete", resultCount: 1 }),
    results: async () => [{ path: "a.txt" }],
    cancel: async () => undefined,
  };
  return { filesystem, process, search };
}

describe("V3 macOS agent candidate", () => {
  it("round-trips bytes through the Keychain reference adapter", async () => {
    const values = new Map<string, string>();
    const run: SecurityCommandRunner = async (args) => {
      const command = args[0];
      const accountIndex = args.indexOf("-a");
      const account = accountIndex >= 0 ? args[accountIndex + 1] : undefined;
      if (!account) throw new Error("account missing");
      if (command === "add-generic-password") {
        const passwordIndex = args.indexOf("-w");
        values.set(account, args[passwordIndex + 1] ?? "");
        return "";
      }
      if (command === "find-generic-password") {
        const value = values.get(account);
        if (value === undefined) throw new Error("not found");
        return value;
      }
      if (command === "delete-generic-password") {
        values.delete(account);
        return "";
      }
      throw new Error("unexpected security command");
    };

    const protector = new MacOSKeychainSecretProtector(
      "com.radlina.test",
      run,
      () => "token-1",
    );
    const plaintext = Buffer.from("macos-secret");
    const reference = await protector.protect(plaintext);
    expect(Buffer.from(reference).toString("utf8")).toBe("keychain:token-1");
    await expect(protector.unprotect(reference)).resolves.toEqual(plaintext);
    await protector.delete(reference);
    await expect(protector.unprotect(reference)).rejects.toThrow(/not found/u);
  });

  it("conforms to the platform-neutral contract with macOS identity", async () => {
    const ports = fakePorts();
    const adapter = createMacOSPlatformAdapter({
      ...ports,
      secrets: new MacOSKeychainSecretProtector(
        "com.radlina.test",
        async () => "",
        () => "token",
      ),
      agentVersion: "3.0.0-alpha.1",
      readiness: async () => ({ ready: true }),
      scheduleRestart: async () => undefined,
      hostname: () => "MacBook",
      architecture: () => "arm64",
    });

    await expect(assertPlatformAdapterConformance(adapter)).resolves.toEqual({
      hostname: "MacBook",
      platform: "macos",
      architecture: "arm64",
      agentVersion: "3.0.0-alpha.1",
      health: "healthy",
    });
  });

  it("binds hello and capability execution to macbook-main", async () => {
    const ports = fakePorts();
    const adapter = createMacOSPlatformAdapter({
      ...ports,
      secrets: new MacOSKeychainSecretProtector(
        "com.radlina.test",
        async () => "",
        () => "token",
      ),
      agentVersion: "3.0.0-alpha.1",
      readiness: async () => ({ ready: true }),
      scheduleRestart: async () => undefined,
      hostname: () => "MacBook",
      architecture: () => "arm64",
    });

    const registry = new CapabilityRegistry();
    registry.register({
      id: "radlina.device",
      version: "3.0.0",
      description: "macOS agent test",
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

    const policy = new V3ExecutionPolicyGuard(
      new PolicyEngine(testConfig("C:\\workspace"), {
        killSwitch: () => false,
        emergencyReadOnly: () => false,
      }),
    );
    const runtime = new V3CapabilityRuntime(
      registry,
      policy,
      { record: async () => "c".repeat(64) },
      new HmacDistributedAuditSigner(Buffer.alloc(32, 8)),
      () => "2026-10-08T00:00:00Z",
    );

    const agent = new MacOSDeviceAgent(adapter, registry, runtime, {
      deviceId: "macbook-main",
      tags: ["primary", "apple"],
      trustState: "trusted",
      identity: {
        deviceId: "macbook-main",
        agentInstanceId: "b2e93471-b496-49f0-85ea-24e3dc70a192",
        agentVersion: "3.0.0-alpha.1",
        publicKeyFingerprint: "a".repeat(64),
        enrolledAt: "2026-10-08T00:00:00Z",
      },
    });

    await expect(agent.hello()).resolves.toMatchObject({
      descriptor: {
        deviceId: "macbook-main",
        platform: "macos",
        architecture: "arm64",
        trustState: "trusted",
      },
    });

    const input = {};
    const auth: AuthInfo = {
      token: "token",
      clientId: "client",
      scopes: ["device:read"],
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    };
    const result = await agent.execute(
      {
        requestId: "86c8ecbd-c8a3-4df2-8fe8-a8a858ca786e",
        workflowExecutionId: "wf-macos",
        nodeId: "health",
        attempt: 1,
        targetDeviceId: "macbook-main",
        capability: "device.health",
        input,
        inputSha256: sha256(canonicalJson(input)),
        timeoutMs: 5_000,
        globalCorrelationId: "corr-macos",
        traceId: "trace-macos",
      },
      {
        auth,
        subject: "owner",
        profile: "test",
        isCancelled: () => false,
      },
    );

    expect(result).toMatchObject({
      ok: true,
      receipt: {
        resolvedDeviceId: "macbook-main",
        terminalState: "completed",
      },
    });
  });
});
