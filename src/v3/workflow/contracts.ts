import * as z from "zod/v4";

export const WORKFLOW_CONTRACT_VERSION = "1.0.0" as const;

export const WORKFLOW_STATES = [
  "queued",
  "running",
  "completed",
  "failed",
  "cancelled",
  "interrupted",
] as const;

export const NODE_STATES = [
  "pending",
  "ready",
  "running",
  "completed",
  "failed",
  "cancelled",
  "interrupted",
  "blocked",
] as const;

export type WorkflowState = (typeof WORKFLOW_STATES)[number];
export type NodeState = (typeof NODE_STATES)[number];

const identifierSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z][A-Za-z0-9._-]*$/u);

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/u);

export const deviceTargetSchema = z
  .object({
    deviceId: z.string().min(1).max(128).optional(),
    capability: z.string().min(1).max(128).optional(),
    platform: z.enum(["windows", "macos"]).optional(),
    approvedTag: z.string().min(1).max(128).optional(),
    architecture: z.enum(["x64", "arm64", "unknown"]).optional(),
    agentVersionRange: z.string().min(1).max(128).optional(),
    health: z.enum(["healthy", "degraded", "unhealthy", "unknown"]).optional(),
  })
  .superRefine((target, context) => {
    const primary = [
      target.deviceId,
      target.capability,
      target.platform,
      target.approvedTag,
    ].filter((value) => value !== undefined);
    if (primary.length !== 1) {
      context.addIssue({
        code: "custom",
        message: "target must specify exactly one primary selector",
      });
    }
  });

export type DeviceTarget = z.infer<typeof deviceTargetSchema>;

export const executionPolicySchema = z.object({
  failureMode: z.enum(["fail-workflow", "block-dependents"]),
  allowDynamicReroute: z.boolean(),
  unknownOutcome: z.enum(["fail", "manual-resume"]),
});

export type ExecutionPolicy = z.infer<typeof executionPolicySchema>;

export const expectedOutputSchema = z.object({
  contractId: z.string().min(1).max(200),
  artifactMode: z.enum(["inline", "artifact", "either"]),
  maxBytes: z.number().int().positive().max(1_073_741_824),
});

export type ExpectedOutput = z.infer<typeof expectedOutputSchema>;

export const workflowNodeSchema = z
  .object({
    id: identifierSchema,
    capability: z.string().min(1).max(128),
    input: z.record(z.string(), z.unknown()),
    dependsOn: z.array(identifierSchema).max(256),
    target: deviceTargetSchema,
    maxAttempts: z.number().int().min(1).max(10),
    timeoutMs: z.number().int().min(100).max(86_400_000),
    executionPolicy: executionPolicySchema,
    expectedOutput: expectedOutputSchema,
  })
  .superRefine((node, context) => {
    if (new Set(node.dependsOn).size !== node.dependsOn.length) {
      context.addIssue({
        code: "custom",
        path: ["dependsOn"],
        message: "dependsOn may not contain duplicate node ids",
      });
    }
    if (node.dependsOn.includes(node.id)) {
      context.addIssue({
        code: "custom",
        path: ["dependsOn"],
        message: "a node may not depend on itself",
      });
    }
    if (node.target.deviceId !== undefined && node.executionPolicy.allowDynamicReroute) {
      context.addIssue({
        code: "custom",
        path: ["executionPolicy", "allowDynamicReroute"],
        message: "exact-device execution may not enable dynamic reroute",
      });
    }
  });

export type WorkflowNode = z.infer<typeof workflowNodeSchema>;

const workflowDefinitionBaseSchema = z.object({
  workflowId: identifierSchema,
  definitionVersion: z.string().min(1).max(64),
  title: z.string().min(1).max(200),
  nodes: z.array(workflowNodeSchema).min(1).max(512),
});

function validateGraph(nodes: WorkflowNode[], context: z.RefinementCtx): void {
  const indexById = new Map<string, number>();
  for (const [index, node] of nodes.entries()) {
    if (indexById.has(node.id)) {
      context.addIssue({
        code: "custom",
        path: ["nodes", index, "id"],
        message: `duplicate node id: ${node.id}`,
      });
    } else {
      indexById.set(node.id, index);
    }
  }

  for (const [index, node] of nodes.entries()) {
    for (const dependency of node.dependsOn) {
      if (!indexById.has(dependency)) {
        context.addIssue({
          code: "custom",
          path: ["nodes", index, "dependsOn"],
          message: `missing dependency: ${dependency}`,
        });
      }
    }
  }

  const color = new Map<string, 0 | 1 | 2>();
  const visit = (nodeId: string, trail: string[]): void => {
    const state = color.get(nodeId) ?? 0;
    if (state === 2) return;
    if (state === 1) {
      context.addIssue({
        code: "custom",
        path: ["nodes"],
        message: `dependency cycle detected: ${[...trail, nodeId].join(" -> ")}`,
      });
      return;
    }

    color.set(nodeId, 1);
    const index = indexById.get(nodeId);
    if (index !== undefined) {
      const node = nodes[index];
      if (node) {
        for (const dependency of node.dependsOn) {
          if (indexById.has(dependency)) visit(dependency, [...trail, nodeId]);
        }
      }
    }
    color.set(nodeId, 2);
  };

  for (const node of nodes) visit(node.id, []);
}

export const workflowDefinitionSchema = workflowDefinitionBaseSchema.superRefine(
  (definition, context) => {
    validateGraph(definition.nodes, context);
  },
);

export type WorkflowDefinition = z.infer<typeof workflowDefinitionSchema>;

export function parseWorkflowDefinition(input: unknown): WorkflowDefinition {
  return workflowDefinitionSchema.parse(input);
}

export const dispatchReceiptSchema = z.object({
  workflowExecutionId: z.string().min(1).max(200),
  nodeId: identifierSchema,
  attempt: z.number().int().positive(),
  resolvedDeviceId: z.string().min(1).max(128),
  capability: z.string().min(1).max(128),
  inputSha256: sha256Schema,
  startedAt: z.string().min(1),
  terminalState: z.enum(["completed", "failed", "cancelled", "interrupted"]),
  outputSha256: z.union([sha256Schema, z.null()]),
  localAuditReceiptHash: sha256Schema,
  globalCorrelationId: z.string().min(1).max(200),
  traceId: z.string().min(1).max(200),
});

export type DispatchReceipt = z.infer<typeof dispatchReceiptSchema>;

export const legacyOperatorStepSchema = z.object({
  id: identifierSchema,
  capability: z.string().min(1).max(128),
  input: z.record(z.string(), z.unknown()),
  maxAttempts: z.number().int().min(1).max(3),
});

export const legacyOperatorPlanSchema = z.object({
  title: z.string().min(1).max(128),
  steps: z.array(legacyOperatorStepSchema).min(1).max(16),
});

export type LegacyOperatorPlan = z.infer<typeof legacyOperatorPlanSchema>;

export type LegacySequentialDependency = {
  id: string;
  dependsOn: string[];
};

export function legacySequentialDependencies(input: unknown): LegacySequentialDependency[] {
  const plan = legacyOperatorPlanSchema.parse(input);
  return plan.steps.map((step, index) => ({
    id: step.id,
    dependsOn: index === 0 ? [] : [plan.steps[index - 1]!.id],
  }));
}
