import os from "node:os";

import { McpServer, type AuthInfo, type CallToolResult } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

import { persistTrustedOwnerConfig } from "./admin/trusted-owner.js";
import { validateConfig } from "./config/index.js";
import { AppError } from "./errors.js";
import type { Risk } from "./policy/engine.js";
import type { AppRuntime } from "./runtime.js";

type ToolContext = { http?: { authInfo?: AuthInfo }; signal?: AbortSignal };
type ToolOptions = {
  tool: string;
  scope: string;
  profile?: string;
  risk?: Risk;
  idempotencyKey?: string;
  auditArgs?: unknown;
};

const profileInput = z.string().min(1).max(100).optional();
const idempotencyInput = z.string().uuid();
const pathInput = z.string().min(1).max(32_768);
const sessionIdInput = z.string().uuid();
const releaseManifestInput = z.string().regex(/^[0-9a-f]{64}$/i);
const releaseIdentityInput = z.union([releaseManifestInput, z.literal("ROOT")]);

function subject(context: ToolContext): string {
  const candidate = context.http?.authInfo?.extra?.["sub"];
  if (typeof candidate === "string") return candidate;
  return context.http?.authInfo?.clientId ?? "unknown";
}

function selectedProfile(runtime: AppRuntime, name?: string) {
  const selected = name ?? runtime.config.policy.defaultProfile;
  const profile = runtime.config.profiles[selected];
  const filesystem = runtime.filesystems.get(selected);
  if (!profile || !filesystem)
    throw new AppError("POLICY_DENIED", `workspace profile ${selected} does not exist`);
  return { name: selected, profile, filesystem };
}

function execute<T>(
  runtime: AppRuntime,
  context: ToolContext,
  args: unknown,
  options: ToolOptions,
  handler: () => Promise<T>,
): Promise<CallToolResult> {
  return runtime.tools.run({
    auth: context.http?.authInfo,
    tool: options.tool,
    scope: options.scope,
    args,
    handler,
    ...(context.signal === undefined ? {} : { signal: context.signal }),
    ...(options.profile === undefined ? {} : { profile: options.profile }),
    ...(options.risk === undefined ? {} : { risk: options.risk }),
    ...(options.idempotencyKey === undefined ? {} : { idempotencyKey: options.idempotencyKey }),
    ...(options.auditArgs === undefined ? {} : { auditArgs: options.auditArgs }),
  });
}

const readAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};
const writeAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};
const destructiveAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: true,
  openWorldHint: false,
};

export function buildMcpServer(runtime: AppRuntime): McpServer {
  const server = new McpServer({ name: "radlina-remote-mcp", version: "0.2.0" });

  server.registerTool(
    "who_am_i",
    {
      description: "Return the authenticated local subject and granted scopes.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(runtime, context, {}, { tool: "who_am_i", scope: "device:read" }, async () => ({
        subject: subject(context),
        clientId: context.http?.authInfo?.clientId,
        scopes: context.http?.authInfo?.scopes ?? [],
        deviceId: os.hostname(),
      })),
  );
  server.registerTool(
    "list_devices",
    {
      description: "List the single workstation managed by this server.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(runtime, context, {}, { tool: "list_devices", scope: "device:read" }, async () => ({
        devices: [{ id: os.hostname(), online: true }],
      })),
  );
  server.registerTool(
    "ping",
    {
      description: "Check authenticated MCP reachability.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(runtime, context, {}, { tool: "ping", scope: "device:read" }, async () => ({
        ok: true,
        timestamp: new Date().toISOString(),
      })),
  );
  server.registerTool(
    "get_capabilities",
    {
      description: "Return enabled profiles, limits, and server capability groups.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(
        runtime,
        context,
        {},
        { tool: "get_capabilities", scope: "device:read" },
        async () => ({
          protocol: "2026-07-28",
          transport: "streamable-http",
          profiles: Object.keys(runtime.config.profiles),
          capabilities: [
            "device",
            "filesystem",
            "search",
            "process",
            "diagnostics",
            "upgrade",
            "trusted-owner",
          ],
          limits: runtime.config.policy,
          trustedOwner:
            runtime.config.profiles[runtime.config.policy.defaultProfile]?.allowShell === true,
          activeReleaseManifest: process.env["RADLINA_ACTIVE_RELEASE_MANIFEST"] ?? "ROOT",
        }),
      ),
  );
  server.registerTool(
    "health",
    {
      description: "Return a minimal health status for the local service.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(runtime, context, {}, { tool: "health", scope: "device:read" }, async () => ({
        status: "healthy",
        uptimeSeconds: Math.floor((Date.now() - runtime.startedAt) / 1000),
      })),
  );
  server.registerTool(
    "version",
    {
      description: "Return server, runtime, and protocol versions.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(runtime, context, {}, { tool: "version", scope: "device:read" }, async () => ({
        server: "0.2.0",
        node: process.version,
        protocol: "2026-07-28",
        activeReleaseManifest: process.env["RADLINA_ACTIVE_RELEASE_MANIFEST"] ?? "ROOT",
        trustedOwner:
          runtime.config.profiles[runtime.config.policy.defaultProfile]?.allowShell === true,
      })),
  );

  server.registerTool(
    "list_directory",
    {
      description: "List one page of an allowed directory.",
      inputSchema: z.object({
        path: pathInput,
        profile: profileInput,
        cursor: z.string().optional(),
        limit: z.number().int().min(1).max(500).default(100),
      }),
      annotations: readAnnotations,
    },
    ({ path, profile, cursor, limit }, context) => {
      const selected = selectedProfile(runtime, profile);
      return execute(
        runtime,
        context,
        { path, profile, cursor, limit },
        { tool: "list_directory", scope: "filesystem:read", profile: selected.name },
        () => selected.filesystem.listDirectory(path, cursor, limit),
      );
    },
  );
  server.registerTool(
    "read_file",
    {
      description: "Read a bounded byte range from an allowed file.",
      inputSchema: z.object({
        path: pathInput,
        profile: profileInput,
        offset: z.number().int().min(0).default(0),
        length: z.number().int().min(1).max(1_048_576).default(65_536),
      }),
      annotations: readAnnotations,
    },
    ({ path, profile, offset, length }, context) => {
      const selected = selectedProfile(runtime, profile);
      return execute(
        runtime,
        context,
        { path, profile, offset, length },
        { tool: "read_file", scope: "filesystem:read", profile: selected.name },
        () => selected.filesystem.readFile(path, offset, length),
      );
    },
  );
  server.registerTool(
    "read_multiple_files",
    {
      description: "Read bounded ranges from up to 32 allowed files.",
      inputSchema: z.object({
        paths: z.array(pathInput).min(1).max(32),
        profile: profileInput,
        offset: z.number().int().min(0).default(0),
        length: z.number().int().min(1).max(1_048_576).default(65_536),
      }),
      annotations: readAnnotations,
    },
    ({ paths, profile, offset, length }, context) => {
      const selected = selectedProfile(runtime, profile);
      return execute(
        runtime,
        context,
        { paths, profile, offset, length },
        { tool: "read_multiple_files", scope: "filesystem:read", profile: selected.name },
        () => selected.filesystem.readMultipleFiles(paths, offset, length),
      );
    },
  );
  server.registerTool(
    "get_file_info",
    {
      description: "Return metadata for one allowed filesystem path.",
      inputSchema: z.object({ path: pathInput, profile: profileInput }),
      annotations: readAnnotations,
    },
    ({ path, profile }, context) => {
      const selected = selectedProfile(runtime, profile);
      return execute(
        runtime,
        context,
        { path, profile },
        { tool: "get_file_info", scope: "filesystem:read", profile: selected.name },
        () => selected.filesystem.getFileInfo(path),
      );
    },
  );

  server.registerTool(
    "create_directory",
    {
      description: "Create a directory below an allowed workspace root.",
      inputSchema: z.object({
        path: pathInput,
        profile: profileInput,
        idempotencyKey: idempotencyInput,
      }),
      annotations: writeAnnotations,
    },
    ({ path, profile, idempotencyKey }, context) => {
      const selected = selectedProfile(runtime, profile);
      return execute(
        runtime,
        context,
        { path, profile },
        {
          tool: "create_directory",
          scope: "filesystem:write",
          profile: selected.name,
          idempotencyKey,
        },
        () => selected.filesystem.createDirectory(path),
      );
    },
  );
  server.registerTool(
    "write_file",
    {
      description: "Atomically write one allowed file with an explicit idempotency key.",
      inputSchema: z.object({
        path: pathInput,
        content: z.string(),
        encoding: z.enum(["utf8", "base64"]).default("utf8"),
        overwrite: z.boolean().default(false),
        profile: profileInput,
        idempotencyKey: idempotencyInput,
      }),
      annotations: writeAnnotations,
    },
    ({ path, content, encoding, overwrite, profile, idempotencyKey }, context) => {
      const selected = selectedProfile(runtime, profile);
      const auditArgs = {
        path,
        encoding,
        overwrite,
        profile,
        content: `[redacted:${Buffer.byteLength(content)} bytes]`,
      };
      return execute(
        runtime,
        context,
        { path, content, encoding, overwrite, profile },
        {
          tool: "write_file",
          scope: "filesystem:write",
          profile: selected.name,
          idempotencyKey,
          auditArgs,
        },
        () => selected.filesystem.writeFile(path, content, encoding, overwrite),
      );
    },
  );
  server.registerTool(
    "edit_block",
    {
      description: "Replace exactly one matching text block in an allowed file.",
      inputSchema: z.object({
        path: pathInput,
        search: z.string().min(1),
        replacement: z.string(),
        profile: profileInput,
        idempotencyKey: idempotencyInput,
      }),
      annotations: writeAnnotations,
    },
    ({ path, search, replacement, profile, idempotencyKey }, context) => {
      const selected = selectedProfile(runtime, profile);
      const auditArgs = {
        path,
        profile,
        search: `[redacted:${Buffer.byteLength(search)} bytes]`,
        replacement: `[redacted:${Buffer.byteLength(replacement)} bytes]`,
      };
      return execute(
        runtime,
        context,
        { path, search, replacement, profile },
        {
          tool: "edit_block",
          scope: "filesystem:write",
          profile: selected.name,
          idempotencyKey,
          auditArgs,
        },
        () => selected.filesystem.editBlock(path, search, replacement),
      );
    },
  );
  server.registerTool(
    "copy",
    {
      description: "Copy an allowed file or directory to an allowed destination.",
      inputSchema: z.object({
        source: pathInput,
        destination: pathInput,
        overwrite: z.boolean().default(false),
        profile: profileInput,
        idempotencyKey: idempotencyInput,
      }),
      annotations: writeAnnotations,
    },
    ({ source, destination, overwrite, profile, idempotencyKey }, context) => {
      const selected = selectedProfile(runtime, profile);
      return execute(
        runtime,
        context,
        { source, destination, overwrite, profile },
        { tool: "copy", scope: "filesystem:write", profile: selected.name, idempotencyKey },
        () => selected.filesystem.copy(source, destination, overwrite),
      );
    },
  );
  server.registerTool(
    "move",
    {
      description: "Move an allowed path without overwriting its destination.",
      inputSchema: z.object({
        source: pathInput,
        destination: pathInput,
        profile: profileInput,
        idempotencyKey: idempotencyInput,
      }),
      annotations: destructiveAnnotations,
    },
    ({ source, destination, profile, idempotencyKey }, context) => {
      const selected = selectedProfile(runtime, profile);
      return execute(
        runtime,
        context,
        { source, destination, profile },
        {
          tool: "move",
          scope: "filesystem:write",
          profile: selected.name,
          risk: "medium",
          idempotencyKey,
        },
        () => selected.filesystem.move(source, destination),
      );
    },
  );
  server.registerTool(
    "trash",
    {
      description:
        "Move an allowed path to a recoverable quarantine after exact-path confirmation; requires admin.",
      inputSchema: z.object({
        path: pathInput,
        confirmationPath: pathInput,
        profile: profileInput,
        idempotencyKey: idempotencyInput,
      }),
      annotations: destructiveAnnotations,
    },
    ({ path, confirmationPath, profile, idempotencyKey }, context) => {
      const selected = selectedProfile(runtime, profile);
      return execute(
        runtime,
        context,
        { path, confirmationPath, profile },
        { tool: "trash", scope: "admin", profile: selected.name, risk: "critical", idempotencyKey },
        () => selected.filesystem.trash(path, confirmationPath),
      );
    },
  );

  server.registerTool(
    "start_search",
    {
      description: "Start a bounded, reconnectable ripgrep search in an allowed root.",
      inputSchema: z.object({
        mode: z.enum(["files", "content"]),
        path: pathInput,
        pattern: z.string().min(1).max(512),
        glob: z.array(z.string().min(1).max(512)).max(32).optional(),
        caseSensitive: z.boolean().default(false),
        literal: z.boolean().default(true),
        maxResults: z.number().int().min(1).max(10_000).default(1000),
        profile: profileInput,
      }),
      annotations: readAnnotations,
    },
    ({ mode, path, pattern, glob, caseSensitive, literal, maxResults, profile }, context) => {
      const selected = selectedProfile(runtime, profile);
      const query = {
        mode,
        path,
        pattern,
        caseSensitive,
        literal,
        maxResults,
        ...(glob === undefined ? {} : { glob }),
      };
      return execute(
        runtime,
        context,
        { ...query, profile },
        { tool: "start_search", scope: "filesystem:read", profile: selected.name },
        () =>
          runtime.searches.start(
            subject(context),
            selected.name,
            selected.filesystem.resolver,
            query,
          ),
      );
    },
  );
  server.registerTool(
    "search_status",
    {
      description: "Return status for a reconnectable search owned by the caller.",
      inputSchema: z.object({ searchId: sessionIdInput }),
      annotations: readAnnotations,
    },
    ({ searchId }, context) =>
      execute(
        runtime,
        context,
        { searchId },
        { tool: "search_status", scope: "filesystem:read" },
        async () => runtime.searches.status(searchId, subject(context)),
      ),
  );
  server.registerTool(
    "search_results",
    {
      description: "Read one deterministic page from a search owned by the caller.",
      inputSchema: z.object({
        searchId: sessionIdInput,
        cursor: z.string().optional(),
        limit: z.number().int().min(1).max(500).default(100),
      }),
      annotations: readAnnotations,
    },
    ({ searchId, cursor, limit }, context) =>
      execute(
        runtime,
        context,
        { searchId, cursor, limit },
        { tool: "search_results", scope: "filesystem:read" },
        () => runtime.searches.results(searchId, subject(context), cursor, limit),
      ),
  );
  server.registerTool(
    "cancel_search",
    {
      description: "Cancel a running search owned by the caller.",
      inputSchema: z.object({ searchId: sessionIdInput, idempotencyKey: idempotencyInput }),
      annotations: writeAnnotations,
    },
    ({ searchId, idempotencyKey }, context) =>
      execute(
        runtime,
        context,
        { searchId },
        { tool: "cancel_search", scope: "filesystem:read", idempotencyKey },
        async () => runtime.searches.cancel(searchId, subject(context)),
      ),
  );

  server.registerTool(
    "list_processes",
    {
      description: "List a bounded snapshot of local process names and identifiers.",
      inputSchema: z.object({ limit: z.number().int().min(1).max(500).default(100) }),
      annotations: readAnnotations,
    },
    ({ limit }, context) =>
      execute(runtime, context, { limit }, { tool: "list_processes", scope: "process:read" }, () =>
        runtime.processes.listProcesses(limit),
      ),
  );
  server.registerTool(
    "start_process",
    {
      description:
        "Start an allowlisted executable without a shell and return a reconnectable session.",
      inputSchema: z.object({
        executable: pathInput,
        args: z.array(z.string().max(4096)).max(128).default([]),
        cwd: pathInput,
        env: z.record(z.string(), z.string().max(4096)).optional(),
        timeoutMs: z.number().int().min(100).max(86_400_000).optional(),
        profile: profileInput,
        idempotencyKey: idempotencyInput,
      }),
      annotations: writeAnnotations,
    },
    ({ executable, args, cwd, env, timeoutMs, profile, idempotencyKey }, context) => {
      const selected = selectedProfile(runtime, profile);
      const input = {
        executable,
        args,
        cwd,
        ...(env === undefined ? {} : { env }),
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
      };
      const auditArgs = {
        ...input,
        profile,
        args: input.args.map(
          (value) =>
            `[sha256:${value.length}:${Buffer.from(value).toString("base64url").slice(0, 12)}]`,
        ),
        env: input.env ? Object.keys(input.env) : [],
      };
      return execute(
        runtime,
        context,
        { ...input, profile },
        {
          tool: "start_process",
          scope: "process:execute",
          profile: selected.name,
          risk: "high",
          idempotencyKey,
          auditArgs,
        },
        () =>
          runtime.processes.start(
            subject(context),
            selected.name,
            selected.profile,
            selected.filesystem.resolver,
            input,
          ),
      );
    },
  );
  server.registerTool(
    "read_process_output",
    {
      description: "Read bounded output from a process session owned by the caller.",
      inputSchema: z.object({
        sessionId: sessionIdInput,
        cursor: z.string().optional(),
        maxBytes: z.number().int().min(1).max(1_048_576).default(65_536),
      }),
      annotations: readAnnotations,
    },
    ({ sessionId, cursor, maxBytes }, context) =>
      execute(
        runtime,
        context,
        { sessionId, cursor, maxBytes },
        { tool: "read_process_output", scope: "process:read" },
        () => runtime.processes.readOutput(sessionId, subject(context), cursor, maxBytes),
      ),
  );
  server.registerTool(
    "interact_with_process",
    {
      description: "Write bounded input to a live process session owned by the caller.",
      inputSchema: z.object({
        sessionId: sessionIdInput,
        input: z.string().max(65_536),
        idempotencyKey: idempotencyInput,
      }),
      annotations: writeAnnotations,
    },
    ({ sessionId, input, idempotencyKey }, context) =>
      execute(
        runtime,
        context,
        { sessionId, input },
        {
          tool: "interact_with_process",
          scope: "process:execute",
          risk: "high",
          idempotencyKey,
          auditArgs: { sessionId, input: `[redacted:${Buffer.byteLength(input)} bytes]` },
        },
        async () => runtime.processes.interact(sessionId, subject(context), input),
      ),
  );
  server.registerTool(
    "terminate_process",
    {
      description:
        "Terminate a caller-owned process session after PID identity verification; force requires admin.",
      inputSchema: z.object({
        sessionId: sessionIdInput,
        force: z.boolean().default(false),
        idempotencyKey: idempotencyInput,
      }),
      annotations: destructiveAnnotations,
    },
    ({ sessionId, force, idempotencyKey }, context) =>
      execute(
        runtime,
        context,
        { sessionId, force },
        {
          tool: "terminate_process",
          scope: force ? "admin" : "process:execute",
          risk: force ? "critical" : "high",
          idempotencyKey,
        },
        () => runtime.processes.terminate(sessionId, subject(context), force),
      ),
  );

  server.registerTool(
    "admin_stage_release",
    {
      description: "Stage one manifest-bound release into the durable local release store.",
      inputSchema: z.object({
        sourceRoot: pathInput,
        expectedManifest: releaseManifestInput,
        idempotencyKey: idempotencyInput,
      }),
      annotations: writeAnnotations,
    },
    ({ sourceRoot, expectedManifest, idempotencyKey }, context) => {
      const selected = selectedProfile(runtime);
      return execute(
        runtime,
        context,
        { sourceRoot, expectedManifest },
        {
          tool: "admin_stage_release",
          scope: "admin",
          profile: selected.name,
          risk: "critical",
          idempotencyKey,
        },
        async () => {
          const resolved = await selected.filesystem.resolver.resolve(sourceRoot, {
            mustExist: true,
          });
          return runtime.upgrades.stage(resolved, expectedManifest);
        },
      );
    },
  );

  server.registerTool(
    "admin_verify_release",
    {
      description: "Verify one staged release against its exact manifest and file hashes.",
      inputSchema: z.object({ manifest: releaseManifestInput }),
      annotations: readAnnotations,
    },
    ({ manifest }, context) =>
      execute(
        runtime,
        context,
        { manifest },
        { tool: "admin_verify_release", scope: "admin" },
        () => runtime.upgrades.verify(manifest),
      ),
  );

  server.registerTool(
    "admin_upgrade_preflight",
    {
      description: "Run fail-closed preflight for a staged release before activation.",
      inputSchema: z.object({ manifest: releaseManifestInput }),
      annotations: readAnnotations,
    },
    ({ manifest }, context) =>
      execute(
        runtime,
        context,
        { manifest },
        { tool: "admin_upgrade_preflight", scope: "admin" },
        () => runtime.upgrades.preflight(manifest),
      ),
  );

  server.registerTool(
    "admin_activate_release",
    {
      description: "Activate one verified release and schedule WinSW self-restart.",
      inputSchema: z.object({ manifest: releaseManifestInput, idempotencyKey: idempotencyInput }),
      annotations: writeAnnotations,
    },
    ({ manifest, idempotencyKey }, context) =>
      execute(
        runtime,
        context,
        { manifest },
        { tool: "admin_activate_release", scope: "admin", risk: "critical", idempotencyKey },
        () => runtime.upgrades.activate(manifest),
      ),
  );

  server.registerTool(
    "admin_upgrade_status",
    {
      description: "Return durable upgrade journal and active release identity.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(runtime, context, {}, { tool: "admin_upgrade_status", scope: "admin" }, () =>
        runtime.upgrades.status(),
      ),
  );

  server.registerTool(
    "admin_rollback_release",
    {
      description: "Rollback to the previous verified release and schedule WinSW self-restart.",
      inputSchema: z.object({ idempotencyKey: idempotencyInput }),
      annotations: destructiveAnnotations,
    },
    ({ idempotencyKey }, context) =>
      execute(
        runtime,
        context,
        {},
        { tool: "admin_rollback_release", scope: "admin", risk: "critical", idempotencyKey },
        () => runtime.upgrades.rollback(),
      ),
  );

  server.registerTool(
    "admin_verify_post_restart",
    {
      description:
        "Verify the running process and durable pointer match an expected healthy release.",
      inputSchema: z.object({ expectedManifest: releaseIdentityInput }),
      annotations: readAnnotations,
    },
    ({ expectedManifest }, context) =>
      execute(
        runtime,
        context,
        { expectedManifest },
        { tool: "admin_verify_post_restart", scope: "admin" },
        () => runtime.upgrades.verifyPostRestart(expectedManifest),
      ),
  );

  server.registerTool(
    "admin_enable_trusted_owner",
    {
      description:
        "Persist full-control trusted-owner mode for the default profile; restart required.",
      inputSchema: z.object({ idempotencyKey: idempotencyInput }),
      annotations: writeAnnotations,
    },
    ({ idempotencyKey }, context) =>
      execute(
        runtime,
        context,
        {},
        {
          tool: "admin_enable_trusted_owner",
          scope: "admin",
          risk: "critical",
          idempotencyKey,
          auditArgs: { mode: "trusted-owner", persist: true },
        },
        async () => {
          const result = await persistTrustedOwnerConfig(runtime.configFile, runtime.config);
          runtime.upgrades.scheduleRestart();
          return result;
        },
      ),
  );

  server.registerTool(
    "get_effective_config",
    {
      description: "Return the non-secret effective runtime configuration.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(
        runtime,
        context,
        {},
        { tool: "get_effective_config", scope: "admin" },
        async () => runtime.config,
      ),
  );
  server.registerTool(
    "validate_config",
    {
      description: "Validate a proposed configuration without applying it.",
      inputSchema: z.object({ config: z.unknown() }),
      annotations: readAnnotations,
    },
    ({ config }, context) =>
      execute(
        runtime,
        context,
        { config },
        { tool: "validate_config", scope: "admin", auditArgs: { config: "[redacted]" } },
        async () => validateConfig(config),
      ),
  );
  server.registerTool(
    "simulate_policy",
    {
      description:
        "Evaluate policy for a proposed tool, scope, profile, and risk without executing it.",
      inputSchema: z.object({
        tool: z.string().min(1).max(100),
        scope: z.string().min(1).max(100),
        profile: profileInput,
        risk: z.enum(["low", "medium", "high", "critical"]).default("low"),
      }),
      annotations: readAnnotations,
    },
    ({ tool, scope, profile, risk }, context) =>
      execute(
        runtime,
        context,
        { tool, scope, profile, risk },
        { tool: "simulate_policy", scope: "admin" },
        async () => runtime.policy.decide(context.http?.authInfo, tool, scope, profile, risk),
      ),
  );
  server.registerTool(
    "recent_tool_calls",
    {
      description: "Return recent sanitized audit records.",
      inputSchema: z.object({ limit: z.number().int().min(1).max(200).default(50) }),
      annotations: readAnnotations,
    },
    ({ limit }, context) =>
      execute(runtime, context, { limit }, { tool: "recent_tool_calls", scope: "admin" }, () =>
        runtime.audit.recent(limit),
      ),
  );
  server.registerTool(
    "active_sessions",
    {
      description: "Return caller-owned active process and search sessions.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(
        runtime,
        context,
        {},
        { tool: "active_sessions", scope: "process:read" },
        async () => ({
          processes: runtime.processes.active(subject(context)),
          searches: runtime.searches.active(subject(context)),
        }),
      ),
  );
  server.registerTool(
    "resource_stats",
    {
      description: "Return bounded local runtime resource statistics.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(runtime, context, {}, { tool: "resource_stats", scope: "admin" }, async () => ({
        uptimeSeconds: process.uptime(),
        memory: process.memoryUsage(),
        loadAverage: os.loadavg(),
        cpuCount: os.cpus().length,
      })),
  );
  server.registerTool(
    "readiness",
    {
      description: "Return authenticated readiness and safety-control state.",
      inputSchema: z.object({}),
      annotations: readAnnotations,
    },
    (_args, context) =>
      execute(runtime, context, {}, { tool: "readiness", scope: "device:read" }, async () => ({
        ready: true,
        killSwitch:
          runtime.store.get("control:killSwitch") ?? String(runtime.config.policy.killSwitch),
        emergencyReadOnly:
          runtime.store.get("control:emergencyReadOnly") ??
          String(runtime.config.policy.emergencyReadOnly),
      })),
  );
  server.registerTool(
    "error_details",
    {
      description: "Return sanitized details for a correlation ID.",
      inputSchema: z.object({ correlationId: z.string().uuid() }),
      annotations: readAnnotations,
    },
    ({ correlationId }, context) =>
      execute(
        runtime,
        context,
        { correlationId },
        { tool: "error_details", scope: "admin" },
        async () => {
          const row = runtime.store.db
            .prepare(
              "SELECT correlation_id,code,message,detail_json,created_at FROM errors WHERE correlation_id=?",
            )
            .get(correlationId) as Record<string, unknown> | undefined;
          if (!row) throw new AppError("NOT_FOUND", "correlation ID was not found");
          return row;
        },
      ),
  );

  return server;
}
