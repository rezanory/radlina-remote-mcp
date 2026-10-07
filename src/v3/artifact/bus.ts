import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import * as z from "zod/v4";

import { canonicalJson, sha256 } from "../../utils/json.js";
import type { DistributedAuditSigner } from "../audit/distributed.js";
import {
  artifactIdFromSha256,
  artifactMetadataSchema,
  artifactReference,
  verifyArtifactIntegrity,
  type ArtifactMetadata,
  type ArtifactReference,
} from "./contracts.js";

export type ArtifactProducerContext = {
  mediaType: string;
  workflowExecutionId: string;
  nodeId: string;
  deviceId: string;
  createdAt: string;
};

const transferReceiptPayloadSchema = z.object({
  globalCorrelationId: z.string().min(1).max(200),
  traceId: z.string().min(1).max(200),
  artifactId: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  sha256: z.string().regex(/^[0-9a-f]{64}$/u),
  size: z.number().int().nonnegative(),
  sourceDeviceId: z.string().min(1).max(128),
  targetDeviceId: z.string().min(1).max(128),
  verifiedAt: z.string().min(1).max(128),
});

export const artifactTransferReceiptSchema = transferReceiptPayloadSchema.extend({
  recordHash: z.string().regex(/^[0-9a-f]{64}$/u),
  signature: z.string().regex(/^[0-9a-f]{64}$/u),
});

export type ArtifactTransferReceipt = z.infer<typeof artifactTransferReceiptSchema>;

export class FilesystemArtifactBus {
  constructor(private readonly root: string) {}

  async publish(bytes: Uint8Array, producer: ArtifactProducerContext): Promise<ArtifactMetadata> {
    if (bytes.byteLength > 1_073_741_824) throw new Error("artifact exceeds maximum size");
    const hash = sha256(bytes);
    const reference: ArtifactReference = {
      artifactId: artifactIdFromSha256(hash),
      sha256: hash,
      size: bytes.byteLength,
    };
    const blobPath = this.blobPath(hash);
    await mkdir(path.dirname(blobPath), { recursive: true });
    try {
      await writeFile(blobPath, bytes, { flag: "wx" });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const existing = await readFile(blobPath);
      verifyArtifactIntegrity(reference, sha256(existing), existing.byteLength);
    }
    return artifactMetadataSchema.parse({
      ...reference,
      mediaType: producer.mediaType,
      producerWorkflowExecutionId: producer.workflowExecutionId,
      producerNodeId: producer.nodeId,
      producerDeviceId: producer.deviceId,
      createdAt: producer.createdAt,
    });
  }

  async fetch(reference: ArtifactReference): Promise<Uint8Array> {
    const blob = await readFile(this.blobPath(reference.sha256));
    verifyArtifactIntegrity(reference, sha256(blob), blob.byteLength);
    return blob;
  }

  async verify(reference: ArtifactReference): Promise<boolean> {
    try {
      await this.fetch(reference);
      return true;
    } catch {
      return false;
    }
  }

  createTransferReceipt(
    metadata: ArtifactMetadata,
    input: {
      globalCorrelationId: string;
      traceId: string;
      sourceDeviceId: string;
      targetDeviceId: string;
      verifiedAt: string;
    },
    signer: DistributedAuditSigner,
  ): ArtifactTransferReceipt {
    const reference = artifactReference(metadata);
    const payload = transferReceiptPayloadSchema.parse({
      ...input,
      ...reference,
    });
    const recordHash = sha256(canonicalJson(payload));
    return artifactTransferReceiptSchema.parse({
      ...payload,
      recordHash,
      signature: signer.sign(recordHash),
    });
  }

  verifyTransferReceipt(receipt: ArtifactTransferReceipt, signer: DistributedAuditSigner): boolean {
    const parsed = artifactTransferReceiptSchema.parse(receipt);
    const { recordHash, signature, ...payload } = parsed;
    const expectedHash = sha256(canonicalJson(payload));
    return recordHash === expectedHash && signer.verify(recordHash, signature);
  }

  private blobPath(hash: string): string {
    return path.join(this.root, hash.slice(0, 2), `${hash}.blob`);
  }
}
