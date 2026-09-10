import { createRuntime, closeRuntime } from "../runtime.js";

function usage(): never {
  console.error(
    "usage: npm run control -- approve <request-id> | owner-trust <list|revoke enrollment-id> | readonly <on|off> | kill <on|off> | verify-audit | idempotency <list|clear key> | status",
  );
  process.exit(2);
}

function parseToggle(value: string | undefined): string {
  if (value === "on") return "true";
  if (value === "off") return "false";
  return usage();
}

async function main(): Promise<void> {
  const runtime = await createRuntime(undefined, { reconcileSessions: false });
  try {
    const command = process.argv[2];
    if (command === "approve") {
      const id = process.argv[3];
      if (!id) usage();
      if (!runtime.auth.approve(id))
        throw new Error("approval request was not found, expired, or already approved");
      console.log(`approved request ${id}`);
      return;
    }
    if (command === "readonly") {
      const value = parseToggle(process.argv[3]);
      runtime.store.set("control:emergencyReadOnly", value);
      console.log(`emergency read-only: ${value}`);
      return;
    }
    if (command === "owner-trust") {
      const action = process.argv[3];
      if (action === "list") {
        console.log(JSON.stringify(runtime.auth.ownerTrustEnrollments()));
        return;
      }
      if (action === "revoke") {
        const enrollmentId = process.argv[4];
        if (!enrollmentId) usage();
        if (!runtime.auth.revokeOwnerEnrollment(enrollmentId))
          throw new Error("owner enrollment was not found or was already revoked");
        console.log(`revoked owner enrollment ${enrollmentId}`);
        return;
      }
      usage();
    }
    if (command === "kill") {
      const value = parseToggle(process.argv[3]);
      runtime.store.set("control:killSwitch", value);
      console.log(`kill switch: ${value}`);
      return;
    }
    if (command === "verify-audit") {
      const result = await runtime.audit.verify(await runtime.audit.files());
      console.log(JSON.stringify(result));
      if (!result.valid) process.exitCode = 1;
      return;
    }
    if (command === "idempotency") {
      const action = process.argv[3];
      if (action === "list") {
        console.log(JSON.stringify(runtime.store.pendingIdempotency()));
        return;
      }
      if (action === "clear") {
        const key = process.argv[4];
        if (!key) usage();
        if (!runtime.store.clearIdempotencyClaim(key)) {
          throw new Error("idempotency claim was not found");
        }
        console.log(`cleared idempotency claim ${key}`);
        return;
      }
      usage();
    }
    if (command === "status") {
      console.log(
        JSON.stringify({
          deviceId: process.env["COMPUTERNAME"] ?? "unknown",
          host: runtime.config.server.host,
          port: runtime.config.server.port,
          publicUrl: runtime.config.server.publicUrl,
          authMode: runtime.config.auth.mode,
          killSwitch:
            runtime.store.get("control:killSwitch") ?? String(runtime.config.policy.killSwitch),
          emergencyReadOnly:
            runtime.store.get("control:emergencyReadOnly") ??
            String(runtime.config.policy.emergencyReadOnly),
        }),
      );
      return;
    }
    usage();
  } finally {
    closeRuntime(runtime);
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "control command failed");
  process.exitCode = 1;
});
