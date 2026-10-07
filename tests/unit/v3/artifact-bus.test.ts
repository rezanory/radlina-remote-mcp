import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { HmacDistributedAuditSigner } from "../../../src/v3/audit/distributed.js";
import { artifactReference } from "../../../src/v3/artifact/contracts.js";
import { FilesystemArtifactBus } from "../../../src/v3/artifact/bus.js";

const roots: string[] = [];

async function bus() {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-artifacts-"));
  roots.push(root);
  return { root, bus: new FilesystemArtifactBus(root) };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("V3 FilesystemArtifactBus", () => {
  it("publishes content-addressed bytes with producer provenance and fetches them with verification", async () => {
    const runtime = await bus();
    const bytes = Buffer.from("artifact-payload");
    const metadata = await runtime.bus.publish(bytes, {
      mediaType: "application/octet-stream",
      workflowExecutionId: "wf-1",
      nodeId: "produce",
      deviceId: "windows-main",
      createdAt: "2026-10-07T15:00:00+03:00",
    });

    expect(metadata.artifactId).toBe(`sha256:${metadata.sha256}`);
    expect(metadata.producerDeviceId).toBe("windows-main");
    await expect(runtime.bus.fetch(artifactReference(metadata))).resolves.toEqual(bytes);
    await expect(runtime.bus.verify(artifactReference(metadata))).resolves.toBe(true);
  });

  it("deduplicates identical content while preserving content identity", async () => {
    const runtime = await bus();
    const bytes = Buffer.from("same-payload");
    const first = await runtime.bus.publish(bytes, {
      mediaType: "text/plain",
      workflowExecutionId: "wf-1",
      nodeId: "a",
      deviceId: "windows-main",
      createdAt: "2026-10-07T15:00:00+03:00",
    });
    const second = await runtime.bus.publish(bytes, {
      mediaType: "text/plain",
      workflowExecutionId: "wf-2",
      nodeId: "b",
      deviceId: "macbook-main",
      createdAt: "2026-10-07T15:01:00+03:00",
    });
    expect(second.artifactId).toBe(first.artifactId);
    expect(second.sha256).toBe(first.sha256);
    expect(second.producerDeviceId).toBe("macbook-main");
  });

  it("fails closed when stored artifact bytes are corrupted", async () => {
    const runtime = await bus();
    const metadata = await runtime.bus.publish(Buffer.from("original"), {
      mediaType: "text/plain",
      workflowExecutionId: "wf-1",
      nodeId: "a",
      deviceId: "windows-main",
      createdAt: "2026-10-07T15:00:00+03:00",
    });
    const hash = metadata.sha256;
    const blobPath = path.join(runtime.root, hash.slice(0, 2), `${hash}.blob`);
    expect((await readFile(blobPath)).toString()).toBe("original");
    await writeFile(blobPath, "tampered");
    await expect(runtime.bus.fetch(artifactReference(metadata))).rejects.toThrow(/mismatch/u);
    await expect(runtime.bus.verify(artifactReference(metadata))).resolves.toBe(false);
  });

  it("creates and verifies signed cross-device transfer receipts", async () => {
    const runtime = await bus();
    const metadata = await runtime.bus.publish(Buffer.from("transfer"), {
      mediaType: "application/octet-stream",
      workflowExecutionId: "wf-1",
      nodeId: "produce",
      deviceId: "windows-main",
      createdAt: "2026-10-07T15:00:00+03:00",
    });
    const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 9));
    const receipt = runtime.bus.createTransferReceipt(
      metadata,
      {
        globalCorrelationId: "corr-1",
        traceId: "trace-1",
        sourceDeviceId: "windows-main",
        targetDeviceId: "macbook-main",
        verifiedAt: "2026-10-07T15:01:00+03:00",
      },
      signer,
    );
    expect(receipt.targetDeviceId).toBe("macbook-main");
    expect(runtime.bus.verifyTransferReceipt(receipt, signer)).toBe(true);
    expect(runtime.bus.verifyTransferReceipt({ ...receipt, targetDeviceId: "other" }, signer)).toBe(
      false,
    );
  });
});
