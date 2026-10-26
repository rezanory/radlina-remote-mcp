import type { AuthInfo, CallToolResult, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import type { AppRuntime } from "../../runtime.js";
import { V3StandaloneReleaseStore } from "./standalone-release-store.js";

type ToolContext = { http?: { authInfo?: AuthInfo }; signal?: AbortSignal };
const read = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const write = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const manifestInput = z.string().regex(/^[a-fA-F0-9]{64}$/u);
const run = (
  runtime: AppRuntime, context: ToolContext, tool: string,
  args: unknown, handler: () => Promise<unknown>, idempotencyKey?: string,
): Promise<CallToolResult> => runtime.tools.run({
  auth: context.http?.authInfo,
  tool, scope: "admin", risk: idempotencyKey ? "critical" : "low",
  args, handler,
  ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
  ...(context.signal === undefined ? {} : { signal: context.signal }),
});

export const V3_STANDALONE_RELEASE_TOOL_NAMES = [
  "admin_stage_release",
  "admin_verify_release",
  "admin_upgrade_preflight",
  "admin_upgrade_status",
  "admin_verify_post_restart",
] as const;

/**
 * These are V2-compatible names, implemented against ONLY an isolated V3
 * release store. No V2 UpgradeManager methods or service-restart scripts.
 */
export function registerV3StandaloneReleaseTools(
  server: McpServer, runtime: AppRuntime, store: V3StandaloneReleaseStore,
): void {
  server.registerTool("admin_stage_release", {
    description: "Stage a manifest-verified V3-only release, without activating any service.",
    inputSchema: z.object({
      sourceRoot: z.string().min(1).max(32768),
      expectedManifest: manifestInput,
      idempotencyKey: z.string().uuid(),
    }),
    annotations: write,
  }, ({ sourceRoot, expectedManifest, idempotencyKey }, context) =>
    run(runtime, context, "admin_stage_release",
      { sourceRoot, expectedManifest }, async () => {
        const name = runtime.config.policy.defaultProfile;
        const filesystem = runtime.filesystems.get(name);
        if (!filesystem) throw new Error("V3 approved filesystem profile is not configured");
        const allowedSource = await filesystem.resolver.resolve(sourceRoot, { mustExist: true });
        return store.stage(allowedSource, expectedManifest);
      }, idempotencyKey));

  server.registerTool("admin_verify_release", {
    description: "Verify a staged release exclusively in the V3 release store.",
    inputSchema: z.object({ manifest: manifestInput }),
    annotations: read,
  }, ({ manifest }, context) =>
    run(runtime, context, "admin_verify_release", { manifest }, () => store.verify(manifest)));

  server.registerTool("admin_upgrade_preflight", {
    description: "Verify the V3 daemon entry and immutable content; no service changes.",
    inputSchema: z.object({ manifest: manifestInput }),
    annotations: read,
  }, ({ manifest }, context) =>
    run(runtime, context, "admin_upgrade_preflight", { manifest }, () => store.preflight(manifest)));

  server.registerTool("admin_upgrade_status", {
    description: "Read V3-only staged and active release metadata without exposing service secrets.",
    inputSchema: z.object({}),
    annotations: read,
  }, (_args, context) =>
    run(runtime, context, "admin_upgrade_status", {}, () => store.status()));

  server.registerTool("admin_verify_post_restart", {
    description: "Confirm the running V3-only service, pinned release and local OAuth health; never touch V2.",
    inputSchema: z.object({ expectedManifest: manifestInput }),
    annotations: read,
  }, ({ expectedManifest }, context) =>
    run(runtime, context, "admin_verify_post_restart", { expectedManifest },
      () => store.verifyPostRestart(expectedManifest)));
}
