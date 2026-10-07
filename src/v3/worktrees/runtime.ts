import path from "node:path";

import * as z from "zod/v4";

import { canonicalJson, sha256 } from "../../utils/json.js";
import type { DistributedAuditSigner } from "../audit/distributed.js";
import type { ArtifactMetadata } from "../artifact/contracts.js";
import { FilesystemArtifactBus } from "../artifact/bus.js";

export type WorktreeCreateInput = {
  repositoryPath: string;
  targetPath: string;
  branchName: string;
  baseRef: string;
};

export interface GitWorktreePort {
  create(input: WorktreeCreateInput): Promise<void>;
  release(repositoryPath: string, targetPath: string): Promise<void>;
  status(targetPath: string): Promise<{ clean: boolean; head: string }>;
}

export interface WorkspaceAuthorizationPort {
  authorize(input: {
    workflowExecutionId: string;
    nodeId: string;
    deviceId: string;
    operation: "workspace.allocate" | "worktree.create" | "worktree.release";
  }): { allowed: boolean; reason: string };
}

const workspaceReceiptPayloadSchema = z.object({
  workspaceId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u),
  workflowExecutionId: z.string().min(1).max(200),
  nodeId: z.string().min(1).max(128),
  deviceId: z.string().min(1).max(128),
  repositoryPath: z.string().min(1),
  targetPath: z.string().min(1),
  branchName: z.string().min(1).max(200),
  baseRef: z.string().min(1).max(200),
  head: z.string().min(1).max(200),
  clean: z.boolean(),
  createdAt: z.string().min(1).max(128),
  globalCorrelationId: z.string().min(1).max(200),
  traceId: z.string().min(1).max(200),
});

export const signedWorkspaceReceiptSchema = workspaceReceiptPayloadSchema.extend({
  recordHash: z.string().regex(/^[0-9a-f]{64}$/u),
  signature: z.string().regex(/^[0-9a-f]{64}$/u),
});

export type SignedWorkspaceReceipt = z.infer<typeof signedWorkspaceReceiptSchema>;

export class WorktreeRuntimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorktreeRuntimeError";
  }
}

export class WorktreeRuntime {
  constructor(
    private readonly workspaceRoot: string,
    private readonly git: GitWorktreePort,
    private readonly authorize: WorkspaceAuthorizationPort,
    private readonly artifacts: FilesystemArtifactBus,
    private readonly signer: DistributedAuditSigner,
    private readonly now: () => string = () => new Date().toISOString(),
  ) {}

  async create(input: {
    workspaceId: string;
    workflowExecutionId: string;
    nodeId: string;
    deviceId: string;
    repositoryPath: string;
    branchName: string;
    baseRef: string;
    globalCorrelationId: string;
    traceId: string;
  }): Promise<{
    targetPath: string;
    receipt: SignedWorkspaceReceipt;
    receiptArtifact: ArtifactMetadata;
  }> {
    const targetPath = this.resolveWorkspacePath(input.workspaceId);
    this.assertAuthorized(input, "workspace.allocate");
    this.assertAuthorized(input, "worktree.create");

    await this.git.create({
      repositoryPath: input.repositoryPath,
      targetPath,
      branchName: input.branchName,
      baseRef: input.baseRef,
    });
    const status = await this.git.status(targetPath);
    const payload = workspaceReceiptPayloadSchema.parse({
      ...input,
      targetPath,
      head: status.head,
      clean: status.clean,
      createdAt: this.now(),
    });
    const recordHash = sha256(canonicalJson(payload));
    const receipt = signedWorkspaceReceiptSchema.parse({
      ...payload,
      recordHash,
      signature: this.signer.sign(recordHash),
    });
    const receiptArtifact = await this.artifacts.publish(
      Buffer.from(canonicalJson(receipt), "utf8"),
      {
        mediaType: "application/vnd.radlina.workspace-receipt+json",
        workflowExecutionId: input.workflowExecutionId,
        nodeId: input.nodeId,
        deviceId: input.deviceId,
        createdAt: payload.createdAt,
      },
    );
    return { targetPath, receipt, receiptArtifact };
  }

  async release(input: {
    workspaceId: string;
    workflowExecutionId: string;
    nodeId: string;
    deviceId: string;
    repositoryPath: string;
  }): Promise<void> {
    const targetPath = this.resolveWorkspacePath(input.workspaceId);
    this.assertAuthorized(input, "worktree.release");
    await this.git.release(input.repositoryPath, targetPath);
  }

  verifyReceipt(receipt: SignedWorkspaceReceipt): boolean {
    const parsed = signedWorkspaceReceiptSchema.parse(receipt);
    const { recordHash, signature, ...payload } = parsed;
    return (
      recordHash === sha256(canonicalJson(payload)) && this.signer.verify(recordHash, signature)
    );
  }

  private resolveWorkspacePath(workspaceId: string): string {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(workspaceId)) {
      throw new WorktreeRuntimeError("invalid workspace id");
    }
    const root = path.resolve(this.workspaceRoot);
    const target = path.resolve(root, workspaceId);
    if (target !== root && !target.startsWith(root + path.sep)) {
      throw new WorktreeRuntimeError("workspace path escapes configured root");
    }
    return target;
  }

  private assertAuthorized(
    input: { workflowExecutionId: string; nodeId: string; deviceId: string },
    operation: "workspace.allocate" | "worktree.create" | "worktree.release",
  ): void {
    const decision = this.authorize.authorize({ ...input, operation });
    if (!decision.allowed) {
      throw new WorktreeRuntimeError(`workspace authorization denied: ${decision.reason}`);
    }
  }
}
