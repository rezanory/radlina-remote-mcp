import * as z from "zod/v4";

import type { CapabilityExecutionContext } from "../../components/contracts.js";
import { CapabilityRegistry } from "../../components/registry.js";
import { canonicalJson, sha256 } from "../../utils/json.js";
import type { DistributedAuditSigner } from "../audit/distributed.js";
import { FilesystemArtifactBus } from "../artifact/bus.js";
import type { ArtifactMetadata } from "../artifact/contracts.js";

const capabilityRiskSchema = z.enum(["low", "medium", "high", "critical"]);

const pluginCapabilitySchema = z.object({
  id: z.string().min(1).max(128),
  version: z.string().min(1).max(64),
  description: z.string().min(1).max(500),
  requiredScope: z.string().min(1).max(128),
  risk: capabilityRiskSchema,
  readOnly: z.boolean(),
  idempotent: z.boolean(),
});

export const pluginManifestSchema = z
  .object({
    pluginId: z.string().regex(/^[a-z][a-z0-9-]{1,63}$/u),
    version: z.string().min(1).max(64),
    description: z.string().min(1).max(500),
    capabilities: z.array(pluginCapabilitySchema).min(1).max(128),
  })
  .superRefine((manifest, context) => {
    const ids = manifest.capabilities.map((capability) => capability.id);
    if (new Set(ids).size !== ids.length) {
      context.addIssue({ code: "custom", message: "plugin capability ids must be unique" });
    }
    for (const capability of manifest.capabilities) {
      if (!capability.id.startsWith(`${manifest.pluginId}.`)) {
        context.addIssue({
          code: "custom",
          message: `plugin capability must be namespaced by ${manifest.pluginId}`,
        });
      }
    }
  });

export type PluginManifest = z.infer<typeof pluginManifestSchema>;

export interface IsolatedPluginHost {
  invoke(input: {
    capability: string;
    payload: unknown;
    context: Pick<CapabilityExecutionContext, "subject" | "profile" | "isCancelled">;
  }): Promise<unknown>;
  shutdown(): Promise<void>;
}

export interface PluginHostFactory {
  load(manifest: PluginManifest): Promise<IsolatedPluginHost>;
}

export type PluginLoadReceipt = {
  pluginId: string;
  version: string;
  capabilityIds: string[];
  loadedAt: string;
  recordHash: string;
  signature: string;
};

export class PluginRuntimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PluginRuntimeError";
  }
}

export class PluginRuntime {
  private readonly hosts = new Map<string, IsolatedPluginHost>();

  constructor(
    private readonly registry: CapabilityRegistry,
    private readonly factory: PluginHostFactory,
    private readonly artifacts: FilesystemArtifactBus,
    private readonly signer: DistributedAuditSigner,
    private readonly now: () => string = () => new Date().toISOString(),
  ) {}

  async load(rawManifest: unknown): Promise<{
    receipt: PluginLoadReceipt;
    receiptArtifact: ArtifactMetadata;
  }> {
    const manifest = pluginManifestSchema.parse(rawManifest);
    if (this.hosts.has(manifest.pluginId)) {
      throw new PluginRuntimeError(`plugin already loaded: ${manifest.pluginId}`);
    }

    const host = await this.factory.load(manifest);
    try {
      this.registry.register({
        id: `plugin.${manifest.pluginId}`,
        version: manifest.version,
        description: manifest.description,
        capabilities: manifest.capabilities.map((capability) => ({
          id: capability.id,
          version: capability.version,
          description: capability.description,
          requiredScope: capability.requiredScope,
          risk: capability.risk,
          readOnly: capability.readOnly,
          idempotent: capability.idempotent,
          execute: async (context, payload) =>
            host.invoke({
              capability: capability.id,
              payload,
              context: {
                subject: context.subject,
                profile: context.profile,
                isCancelled: context.isCancelled,
              },
            }),
        })),
      });
    } catch (error) {
      await host.shutdown();
      throw error;
    }
    this.hosts.set(manifest.pluginId, host);

    const payload = {
      pluginId: manifest.pluginId,
      version: manifest.version,
      capabilityIds: manifest.capabilities.map((capability) => capability.id).sort(),
      loadedAt: this.now(),
    };
    const recordHash = sha256(canonicalJson(payload));
    const receipt: PluginLoadReceipt = {
      ...payload,
      recordHash,
      signature: this.signer.sign(recordHash),
    };
    const receiptArtifact = await this.artifacts.publish(
      Buffer.from(canonicalJson(receipt), "utf8"),
      {
        mediaType: "application/vnd.radlina.plugin-load-receipt+json",
        workflowExecutionId: "plugin-runtime",
        nodeId: manifest.pluginId,
        deviceId: "control-plane",
        createdAt: payload.loadedAt,
      },
    );
    return { receipt, receiptArtifact };
  }

  async unload(pluginId: string): Promise<boolean> {
    const host = this.hosts.get(pluginId);
    if (!host) return false;
    this.registry.unregister(`plugin.${pluginId}`);
    this.hosts.delete(pluginId);
    await host.shutdown();
    return true;
  }

  list(): string[] {
    return [...this.hosts.keys()].sort();
  }

  verifyLoadReceipt(receipt: PluginLoadReceipt): boolean {
    const { recordHash, signature, ...payload } = receipt;
    return (
      recordHash === sha256(canonicalJson(payload)) && this.signer.verify(recordHash, signature)
    );
  }
}
