import * as z from "zod/v4";

export const ARTIFACT_CONTRACT_VERSION = "1.0.0" as const;

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/u);
const artifactIdSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);

export const artifactMetadataSchema = z
  .object({
    artifactId: artifactIdSchema,
    sha256: sha256Schema,
    size: z.number().int().nonnegative().max(1_073_741_824),
    mediaType: z.string().min(1).max(255),
    producerWorkflowExecutionId: z.string().min(1).max(200),
    producerNodeId: z.string().min(1).max(128),
    producerDeviceId: z.string().min(1).max(128),
    createdAt: z.string().min(1).max(128),
  })
  .superRefine((metadata, context) => {
    if (metadata.artifactId !== artifactIdFromSha256(metadata.sha256)) {
      context.addIssue({
        code: "custom",
        path: ["artifactId"],
        message: "artifactId must be the content-addressed SHA-256 identity",
      });
    }
  });

export type ArtifactMetadata = z.infer<typeof artifactMetadataSchema>;

export const artifactReferenceSchema = z.object({
  artifactId: artifactIdSchema,
  sha256: sha256Schema,
  size: z.number().int().nonnegative().max(1_073_741_824),
});

export type ArtifactReference = z.infer<typeof artifactReferenceSchema>;

export class ArtifactIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArtifactIntegrityError";
  }
}

export function artifactIdFromSha256(sha256: string): string {
  const parsed = sha256Schema.parse(sha256);
  return `sha256:${parsed}`;
}

export function parseArtifactMetadata(input: unknown): ArtifactMetadata {
  return artifactMetadataSchema.parse(input);
}

export function artifactReference(metadata: ArtifactMetadata): ArtifactReference {
  return {
    artifactId: metadata.artifactId,
    sha256: metadata.sha256,
    size: metadata.size,
  };
}

export function verifyArtifactIntegrity(
  expected: ArtifactReference,
  actualSha256: string,
  actualSize: number,
): void {
  const normalizedSha = sha256Schema.parse(actualSha256);
  if (!Number.isSafeInteger(actualSize) || actualSize < 0) {
    throw new ArtifactIntegrityError("actual artifact size is invalid");
  }
  if (expected.sha256 !== normalizedSha) {
    throw new ArtifactIntegrityError(
      `artifact SHA-256 mismatch: expected ${expected.sha256}, got ${normalizedSha}`,
    );
  }
  if (expected.size !== actualSize) {
    throw new ArtifactIntegrityError(
      `artifact size mismatch: expected ${expected.size}, got ${actualSize}`,
    );
  }
  if (expected.artifactId !== artifactIdFromSha256(normalizedSha)) {
    throw new ArtifactIntegrityError("artifact id does not match verified content hash");
  }
}
