import { describe, expect, it } from "vitest";

import {
  artifactIdFromSha256,
  artifactReference,
  ArtifactIntegrityError,
  parseArtifactMetadata,
  verifyArtifactIntegrity,
} from "../../../src/v3/artifact/contracts.js";

const hash = "a".repeat(64);

function metadata(overrides: Record<string, unknown> = {}) {
  return parseArtifactMetadata({
    artifactId: `sha256:${hash}`,
    sha256: hash,
    size: 42,
    mediaType: "application/octet-stream",
    producerWorkflowExecutionId: "wf-1",
    producerNodeId: "node-1",
    producerDeviceId: "windows-main",
    createdAt: "2026-10-07T12:00:00+03:00",
    ...overrides,
  });
}

describe("V3 artifact contracts", () => {
  it("derives the artifact id directly from the SHA-256 content identity", () => {
    expect(artifactIdFromSha256(hash)).toBe(`sha256:${hash}`);
  });

  it("accepts metadata containing the frozen producer provenance fields", () => {
    const parsed = metadata();
    expect(parsed.producerWorkflowExecutionId).toBe("wf-1");
    expect(parsed.producerNodeId).toBe("node-1");
    expect(parsed.producerDeviceId).toBe("windows-main");
  });

  it("rejects metadata whose artifact id does not match the content hash", () => {
    expect(() =>
      metadata({
        artifactId: `sha256:${"b".repeat(64)}`,
      }),
    ).toThrow(/content-addressed SHA-256 identity/u);
  });

  it("produces a bounded transfer reference without changing workflow ownership", () => {
    expect(artifactReference(metadata())).toEqual({
      artifactId: `sha256:${hash}`,
      sha256: hash,
      size: 42,
    });
  });

  it("accepts a consumer integrity check only when hash, size, and id all match", () => {
    expect(() => verifyArtifactIntegrity(artifactReference(metadata()), hash, 42)).not.toThrow();
  });

  it("fails closed on hash mismatch", () => {
    expect(() =>
      verifyArtifactIntegrity(artifactReference(metadata()), "b".repeat(64), 42),
    ).toThrow(ArtifactIntegrityError);
  });

  it("fails closed on size mismatch or invalid actual size", () => {
    expect(() => verifyArtifactIntegrity(artifactReference(metadata()), hash, 43)).toThrow(
      /size mismatch/u,
    );
    expect(() => verifyArtifactIntegrity(artifactReference(metadata()), hash, -1)).toThrow(
      /size is invalid/u,
    );
  });
});
