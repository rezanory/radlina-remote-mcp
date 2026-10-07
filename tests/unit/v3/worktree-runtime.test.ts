import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { HmacDistributedAuditSigner } from "../../../src/v3/audit/distributed.js";
import { FilesystemArtifactBus } from "../../../src/v3/artifact/bus.js";
import {
  WorktreeRuntime,
  WorktreeRuntimeError,
  type GitWorktreePort,
} from "../../../src/v3/worktrees/runtime.js";

const roots: string[] = [];

async function runtime(options: { allowed?: boolean } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-worktree-"));
  roots.push(root);
  const create = vi.fn(async () => undefined);
  const release = vi.fn(async () => undefined);
  const status = vi.fn(async () => ({ clean: true, head: "abc123" }));
  const git: GitWorktreePort = { create, release, status };
  const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 5));
  return {
    root,
    git,
    create,
    release,
    status,
    signer,
    runtime: new WorktreeRuntime(
      path.join(root, "workspaces"),
      git,
      {
        authorize: () => ({
          allowed: options.allowed ?? true,
          reason: options.allowed === false ? "denied" : "allowed",
        }),
      },
      new FilesystemArtifactBus(path.join(root, "artifacts")),
      signer,
      () => "2026-10-07T15:00:00+03:00",
    ),
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("V3 worktree runtime", () => {
  it("creates one authorized worktree and emits a signed artifact-backed receipt", async () => {
    const value = await runtime();
    const result = await value.runtime.create({
      workspaceId: "wf-1-node-a",
      workflowExecutionId: "wf-1",
      nodeId: "node-a",
      deviceId: "windows-main",
      repositoryPath: "C:\\repo",
      branchName: "lane/a",
      baseRef: "main",
      globalCorrelationId: "corr-1",
      traceId: "trace-1",
    });
    expect(value.create).toHaveBeenCalledWith(
      expect.objectContaining({
        targetPath: path.join(value.root, "workspaces", "wf-1-node-a"),
        branchName: "lane/a",
      }),
    );
    expect(result.receipt.clean).toBe(true);
    expect(result.receipt.head).toBe("abc123");
    expect(result.receiptArtifact.mediaType).toContain("workspace-receipt");
    expect(value.runtime.verifyReceipt(result.receipt)).toBe(true);
  });

  it("fails before worktree creation when authorization denies the operation", async () => {
    const value = await runtime({ allowed: false });
    await expect(
      value.runtime.create({
        workspaceId: "wf-1-node-a",
        workflowExecutionId: "wf-1",
        nodeId: "node-a",
        deviceId: "windows-main",
        repositoryPath: "C:\\repo",
        branchName: "lane/a",
        baseRef: "main",
        globalCorrelationId: "corr-1",
        traceId: "trace-1",
      }),
    ).rejects.toThrow(/authorization denied/u);
    expect(value.create).not.toHaveBeenCalled();
  });

  it("rejects path-traversal workspace ids", async () => {
    const value = await runtime();
    await expect(
      value.runtime.create({
        workspaceId: "../escape",
        workflowExecutionId: "wf-1",
        nodeId: "node-a",
        deviceId: "windows-main",
        repositoryPath: "C:\\repo",
        branchName: "lane/a",
        baseRef: "main",
        globalCorrelationId: "corr-1",
        traceId: "trace-1",
      }),
    ).rejects.toThrow(WorktreeRuntimeError);
    expect(value.create).not.toHaveBeenCalled();
  });

  it("releases only the resolved workspace path after authorization", async () => {
    const value = await runtime();
    await value.runtime.release({
      workspaceId: "wf-1-node-a",
      workflowExecutionId: "wf-1",
      nodeId: "node-a",
      deviceId: "windows-main",
      repositoryPath: "C:\\repo",
    });
    expect(value.release).toHaveBeenCalledWith(
      "C:\\repo",
      path.join(value.root, "workspaces", "wf-1-node-a"),
    );
  });

  it("detects receipt tampering", async () => {
    const value = await runtime();
    const result = await value.runtime.create({
      workspaceId: "wf-1-node-a",
      workflowExecutionId: "wf-1",
      nodeId: "node-a",
      deviceId: "windows-main",
      repositoryPath: "C:\\repo",
      branchName: "lane/a",
      baseRef: "main",
      globalCorrelationId: "corr-1",
      traceId: "trace-1",
    });
    expect(value.runtime.verifyReceipt({ ...result.receipt, head: "tampered" })).toBe(false);
  });
});
