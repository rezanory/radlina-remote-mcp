import path from "node:path";

import * as z from "zod/v4";

const positiveInt = z.number().int().positive();
const absoluteWindowsPath = z
  .string()
  .min(3)
  .refine((value) => path.win32.isAbsolute(value), {
    message: "must be an absolute Windows path",
  });

export const commandRuleSchema = z.strictObject({
  executable: absoluteWindowsPath,
  argumentPatterns: z.array(z.string().min(1)).max(64).default([]),
});

export const profileSchema = z.strictObject({
  roots: z.array(absoluteWindowsPath).min(1).max(32),
  commands: z.array(commandRuleSchema).max(64).default([]),
  allowShell: z.boolean().default(false),
  allowTrash: z.boolean().default(false),
  envAllowlist: z
    .array(z.string().regex(/^[A-Z_][A-Z0-9_]*$/i))
    .max(64)
    .default([]),
});

export const configSchema = z
  .strictObject({
    server: z.strictObject({
      host: z.enum(["127.0.0.1", "localhost", "::1"]).default("127.0.0.1"),
      port: z.number().int().min(1024).max(65535).default(7337),
      publicUrl: z.url(),
      allowedHosts: z.array(z.string().min(1)).min(1).max(32),
      allowedOrigins: z.array(z.string().min(1)).max(32).default([]),
      requestBodyBytes: positiveInt.max(10 * 1024 * 1024).default(1024 * 1024),
      requestTimeoutMs: positiveInt.max(120_000).default(30_000),
    }),
    auth: z.strictObject({
      mode: z.enum(["internal", "external"]),
      externalIssuer: z.url().optional(),
      externalJwksUrl: z.url().optional(),
      accessTokenTtlSeconds: positiveInt.max(3600).default(3600),
      refreshTokenTtlSeconds: positiveInt.max(30 * 24 * 3600).default(7 * 24 * 3600),
      refreshReplayGraceSeconds: positiveInt.max(300).default(30),
      pairingCodeTtlSeconds: positiveInt.max(3600).default(600),
      allowedRedirectHosts: z.array(z.string().min(1)).min(1).max(32),
    }),
    policy: z.strictObject({
      defaultProfile: z.string().min(1),
      emergencyReadOnly: z.boolean().default(false),
      killSwitch: z.boolean().default(false),
      maxConcurrentRequests: positiveInt.max(128).default(8),
      rateLimitPerMinute: positiveInt.max(10_000).default(60),
      maxFileBytes: positiveInt.max(1024 * 1024 * 1024).default(10 * 1024 * 1024),
      maxOutputBytes: positiveInt.max(100 * 1024 * 1024).default(1024 * 1024),
      maxProcessRuntimeMs: positiveInt.max(24 * 3600 * 1000).default(900_000),
      maxSearchRuntimeMs: positiveInt.max(3600 * 1000).default(120_000),
      maxSessions: positiveInt.max(256).default(12),
    }),
    reliability: z
      .strictObject({
        enabled: z.boolean().default(true),
        probeIntervalMs: positiveInt.min(5_000).max(300_000).default(30_000),
        failureThreshold: positiveInt.min(1).max(10).default(3),
        auditVerifyIntervalMs: positiveInt.min(30_000).max(3_600_000).default(300_000),
        eventRetention: positiveInt.min(100).max(10_000).default(2_000),
      })
      .default({
        enabled: true,
        probeIntervalMs: 30_000,
        failureThreshold: 3,
        auditVerifyIntervalMs: 300_000,
        eventRetention: 2_000,
      }),
    dependencies: z.strictObject({
      ripgrepExecutable: absoluteWindowsPath,
    }),
    profiles: z.record(z.string().min(1), profileSchema),
    storage: z.strictObject({ directory: absoluteWindowsPath }),
    audit: z.strictObject({
      directory: absoluteWindowsPath,
      rotateBytes: positiveInt.min(64 * 1024).max(1024 * 1024 * 1024),
      userRedactionPatterns: z.array(z.string()).max(32).default([]),
    }),
  })
  .superRefine((value, context) => {
    if (!value.profiles[value.policy.defaultProfile]) {
      context.addIssue({
        code: "custom",
        path: ["policy", "defaultProfile"],
        message: "defaultProfile must reference an existing profile",
      });
    }
    if (
      value.auth.mode === "external" &&
      (!value.auth.externalIssuer || !value.auth.externalJwksUrl)
    ) {
      context.addIssue({
        code: "custom",
        path: ["auth"],
        message: "external mode requires externalIssuer and externalJwksUrl",
      });
    }
    const publicUrl = new URL(value.server.publicUrl);
    const local = ["127.0.0.1", "localhost", "::1"].includes(publicUrl.hostname);
    if (!local && publicUrl.protocol !== "https:") {
      context.addIssue({
        code: "custom",
        path: ["server", "publicUrl"],
        message: "non-loopback publicUrl must use HTTPS",
      });
    }
  });

export type AppConfig = z.infer<typeof configSchema>;
export type WorkspaceProfile = z.infer<typeof profileSchema>;
