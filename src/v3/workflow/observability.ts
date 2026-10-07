export type WorkflowTelemetryEvent =
  | { type: "workflow.submitted"; workflowExecutionId: string; at: number }
  | { type: "workflow.completed"; workflowExecutionId: string; at: number; durationMs: number }
  | { type: "workflow.failed"; workflowExecutionId: string; at: number; durationMs: number }
  | { type: "node.ready"; workflowExecutionId: string; nodeId: string; at: number }
  | {
      type: "node.dispatched";
      workflowExecutionId: string;
      nodeId: string;
      deviceId: string;
      at: number;
    }
  | {
      type: "node.completed";
      workflowExecutionId: string;
      nodeId: string;
      at: number;
      durationMs: number;
    }
  | {
      type: "node.failed";
      workflowExecutionId: string;
      nodeId: string;
      at: number;
      durationMs: number;
    }
  | { type: "node.retry"; workflowExecutionId: string; nodeId: string; at: number }
  | { type: "workflow.recovery"; workflowExecutionId: string; at: number };

export interface WorkflowTelemetrySink {
  emit(event: WorkflowTelemetryEvent): void;
}

export type WorkflowMetricsSnapshot = {
  counters: Record<string, number>;
  observations: Record<string, { count: number; min: number; max: number; average: number }>;
};

export class InMemoryWorkflowTelemetry implements WorkflowTelemetrySink {
  private readonly events: WorkflowTelemetryEvent[] = [];
  private readonly counters = new Map<string, number>();
  private readonly observations = new Map<string, number[]>();

  emit(event: WorkflowTelemetryEvent): void {
    if ("durationMs" in event && (!Number.isFinite(event.durationMs) || event.durationMs < 0)) {
      throw new Error("telemetry observation must be finite");
    }

    this.events.push(event);
    this.increment(event.type);

    if ("durationMs" in event) {
      this.observe(`${event.type}.duration_ms`, event.durationMs);
    }
    if (event.type === "node.dispatched") {
      this.increment(`node.dispatched.device.${event.deviceId}`);
    }
  }

  recent(limit = 100): WorkflowTelemetryEvent[] {
    const bounded = Math.min(Math.max(Math.trunc(limit), 1), 1000);
    return this.events.slice(-bounded);
  }

  snapshot(): WorkflowMetricsSnapshot {
    const counters: Record<string, number> = {};
    for (const [name, value] of [...this.counters.entries()].sort(([a], [b]) =>
      a.localeCompare(b),
    )) {
      counters[name] = value;
    }

    const observations: WorkflowMetricsSnapshot["observations"] = {};
    for (const [name, values] of [...this.observations.entries()].sort(([a], [b]) =>
      a.localeCompare(b),
    )) {
      const total = values.reduce((sum, value) => sum + value, 0);
      observations[name] = {
        count: values.length,
        min: Math.min(...values),
        max: Math.max(...values),
        average: total / values.length,
      };
    }
    return { counters, observations };
  }

  private increment(name: string): void {
    this.counters.set(name, (this.counters.get(name) ?? 0) + 1);
  }

  private observe(name: string, value: number): void {
    if (!Number.isFinite(value) || value < 0)
      throw new Error("telemetry observation must be finite");
    const values = this.observations.get(name) ?? [];
    values.push(value);
    this.observations.set(name, values);
  }
}

export class WorkflowTraceTimer {
  constructor(
    private readonly now: () => number = () => Date.now(),
    private readonly sink: WorkflowTelemetrySink,
  ) {}

  startWorkflow(workflowExecutionId: string): () => number {
    const started = this.now();
    this.sink.emit({ type: "workflow.submitted", workflowExecutionId, at: started });
    return () => Math.max(0, this.now() - started);
  }

  startNode(
    workflowExecutionId: string,
    nodeId: string,
    deviceId: string,
  ): { complete: () => void; fail: () => void } {
    const started = this.now();
    this.sink.emit({
      type: "node.dispatched",
      workflowExecutionId,
      nodeId,
      deviceId,
      at: started,
    });
    const terminal = (type: "node.completed" | "node.failed") => {
      const ended = this.now();
      this.sink.emit({
        type,
        workflowExecutionId,
        nodeId,
        at: ended,
        durationMs: Math.max(0, ended - started),
      });
    };
    return {
      complete: () => terminal("node.completed"),
      fail: () => terminal("node.failed"),
    };
  }
}
