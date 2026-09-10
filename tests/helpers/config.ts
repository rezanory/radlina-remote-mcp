import path from "node:path";

import type { AppConfig } from "../../src/config/schema.js";

export function testConfig(root: string): AppConfig {
  return {
    server: {
      host: "127.0.0.1",
      port: 7337,
      publicUrl: "http://127.0.0.1:7337",
      allowedHosts: ["127.0.0.1", "localhost"],
      allowedOrigins: [],
      requestBodyBytes: 1_048_576,
      requestTimeoutMs: 30_000,
    },
    auth: {
      mode: "internal",
      accessTokenTtlSeconds: 3600,
      refreshTokenTtlSeconds: 7 * 86_400,
      refreshReplayGraceSeconds: 30,
      pairingCodeTtlSeconds: 600,
      allowedRedirectHosts: ["127.0.0.1", "localhost", "chatgpt.com", "openai.com"],
    },
    policy: {
      defaultProfile: "test",
      emergencyReadOnly: false,
      killSwitch: false,
      maxConcurrentRequests: 8,
      rateLimitPerMinute: 60,
      maxFileBytes: 10 * 1024 * 1024,
      maxOutputBytes: 1024 * 1024,
      maxProcessRuntimeMs: 15_000,
      maxSearchRuntimeMs: 15_000,
      maxSessions: 4,
    },
    reliability: {
      enabled: true,
      probeIntervalMs: 30_000,
      failureThreshold: 2,
      auditVerifyIntervalMs: 30_000,
      eventRetention: 500,
    },
    dependencies: { ripgrepExecutable: process.execPath },
    profiles: {
      test: {
        roots: [root],
        commands: [],
        allowShell: false,
        allowTrash: false,
        envAllowlist: [],
      },
    },
    storage: { directory: path.win32.join(root, ".state") },
    audit: {
      directory: path.win32.join(root, ".state", "audit"),
      rotateBytes: 64 * 1024,
      userRedactionPatterns: [],
    },
  };
}
