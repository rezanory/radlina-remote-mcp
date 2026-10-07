import { spawn, type ChildProcess } from "node:child_process";

import type { IsolatedPluginHost, PluginHostFactory, PluginManifest } from "./runtime.js";

export interface PluginSourceResolver {
  resolve(manifest: PluginManifest): Promise<string>;
}

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

type ChildMessage =
  | { type: "ready" }
  | { type: "result"; id: string; ok: true; result: unknown }
  | { type: "result"; id: string; ok: false; error: string };

const BOOTSTRAP = String.raw`
let handler;
let allowed = new Set();

function reply(message) {
  if (typeof process.send === "function") process.send(message);
}

process.on("message", async (message) => {
  if (!message || typeof message !== "object") return;

  if (message.type === "init") {
    allowed = new Set(Array.isArray(message.capabilities) ? message.capabilities : []);
    handler = (0, eval)(message.source);
    if (typeof handler !== "function") {
      throw new Error("plugin source must evaluate to a function");
    }
    reply({ type: "ready" });
    return;
  }

  if (message.type !== "invoke" || typeof message.id !== "string") return;
  if (!handler) {
    reply({ type: "result", id: message.id, ok: false, error: "plugin host is not initialized" });
    return;
  }
  if (!allowed.has(message.capability)) {
    reply({
      type: "result",
      id: message.id,
      ok: false,
      error: "capability is not declared by plugin manifest",
    });
    return;
  }

  try {
    const result = await handler({
      capability: message.capability,
      payload: message.payload,
      context: message.context,
    });
    reply({ type: "result", id: message.id, ok: true, result: result ?? null });
  } catch (error) {
    reply({
      type: "result",
      id: message.id,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
});
`;

export class ProcessIsolatedPluginHost implements IsolatedPluginHost {
  private readonly pending = new Map<string, PendingRequest>();
  private sequence = 0;
  private ready = false;
  private closed = false;

  private constructor(
    private readonly child: ChildProcess,
    private readonly timeoutMs: number,
  ) {
    child.on("message", (message) => this.onMessage(message as ChildMessage));
    child.on("exit", (code, signal) => {
      this.closed = true;
      this.ready = false;
      const error = new Error(
        `plugin host exited before request completion: code=${String(code)} signal=${String(signal)}`,
      );
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(error);
      }
      this.pending.clear();
    });
  }

  static async create(input: {
    nodeExecutable: string;
    source: string;
    capabilityIds: string[];
    timeoutMs: number;
  }): Promise<ProcessIsolatedPluginHost> {
    const child = spawn(input.nodeExecutable, ["--permission", "-e", BOOTSTRAP], {
      stdio: ["ignore", "ignore", "pipe", "ipc"],
      env: {},
      windowsHide: true,
    });
    const host = new ProcessIsolatedPluginHost(child, input.timeoutMs);
    await host.initialize(input.source, input.capabilityIds);
    return host;
  }

  async invoke(input: {
    capability: string;
    payload: unknown;
    context: { subject: string; profile: string; isCancelled: () => boolean };
  }): Promise<unknown> {
    if (this.closed || !this.ready) throw new Error("plugin host is unavailable");
    if (!this.child.connected) throw new Error("plugin host IPC is disconnected");

    const id = `plugin-${++this.sequence}`;
    const context = {
      subject: input.context.subject,
      profile: input.context.profile,
      cancelled: input.context.isCancelled(),
    };

    return await new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`plugin invocation timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.send?.({
        type: "invoke",
        id,
        capability: input.capability,
        payload: input.payload,
        context,
      });
    });
  }

  async shutdown(): Promise<void> {
    if (this.closed) return;
    this.ready = false;
    this.closed = true;
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        this.child.kill();
        resolve();
      }, 2_000);
      this.child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
      this.child.kill();
    });
  }

  private async initialize(source: string, capabilityIds: string[]): Promise<void> {
    if (!this.child.connected) throw new Error("plugin host IPC failed to initialize");
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        cleanup();
        reject(error);
      };
      const onMessage = (message: unknown) => {
        if (
          message &&
          typeof message === "object" &&
          (message as { type?: string }).type === "ready"
        ) {
          cleanup();
          this.ready = true;
          resolve();
        }
      };
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error("plugin host initialization timed out"));
      }, this.timeoutMs);
      const cleanup = () => {
        clearTimeout(timer);
        this.child.off("error", onError);
        this.child.off("message", onMessage);
      };

      this.child.once("error", onError);
      this.child.on("message", onMessage);
      this.child.send?.({ type: "init", source, capabilities: capabilityIds });
    });
  }

  private onMessage(message: ChildMessage): void {
    if (message.type !== "result") return;
    const pending = this.pending.get(message.id);
    if (!pending) return;
    this.pending.delete(message.id);
    clearTimeout(pending.timer);
    if (message.ok) pending.resolve(message.result);
    else pending.reject(new Error(message.error));
  }
}

export class ProcessIsolatedPluginHostFactory implements PluginHostFactory {
  constructor(
    private readonly nodeExecutable: string,
    private readonly sources: PluginSourceResolver,
    private readonly timeoutMs = 30_000,
  ) {
    if (!(timeoutMs > 0)) throw new Error("plugin host timeout must be positive");
  }

  async load(manifest: PluginManifest): Promise<IsolatedPluginHost> {
    return await ProcessIsolatedPluginHost.create({
      nodeExecutable: this.nodeExecutable,
      source: await this.sources.resolve(manifest),
      capabilityIds: manifest.capabilities.map((capability) => capability.id),
      timeoutMs: this.timeoutMs,
    });
  }
}
