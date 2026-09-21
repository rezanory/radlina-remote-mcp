export type OperatorJobStatus =
  "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";

export type OperatorStepStatus =
  "pending" | "running" | "completed" | "failed" | "cancelled" | "interrupted";

export type OperatorStepSpec = {
  id: string;
  capability: string;
  input: Record<string, unknown>;
  maxAttempts: number;
};

export type OperatorPlan = {
  title: string;
  steps: OperatorStepSpec[];
};
