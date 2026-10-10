import path from "node:path";

import { AuthService } from "../../src/auth/service.js";
import { loadConfig } from "../../src/config/index.js";
import { configSchema } from "../../src/config/schema.js";
import { Store } from "../../src/persistence/store.js";

/**
 * Local, explicit owner action for the V3 isolated OAuth store.
 * This command cannot touch V2's OAuth database or approve a request automatically.
 */
const [command, approvalId] = process.argv.slice(2);
const stateRoot = process.env["RADLINA_V3_OAUTH_STATE_DIRECTORY"];
const publicValue = process.env["RADLINA_V3_PUBLIC_URL"];
if (
  command !== "approve" ||
  !approvalId ||
  !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(approvalId)
) {
  throw new Error("Usage: v3-oauth-approve.ts approve <exact-request-uuid>");
}
if (!stateRoot || !path.isAbsolute(stateRoot) || !publicValue) {
  throw new Error("V3 OAuth owner approval requires explicit V3 state directory and public URL");
}
const base = await loadConfig();
const publicUrl = new URL(publicValue);
if (publicUrl.protocol !== "https:" || publicUrl.origin === new URL(base.server.publicUrl).origin) {
  throw new Error("V3 owner approval requires a separate validated HTTPS issuer");
}
const root = path.resolve(stateRoot).toLowerCase();
const v2root = path.resolve(base.storage.directory).toLowerCase();
if (root === v2root || root.startsWith(v2root + path.sep) || v2root.startsWith(root + path.sep)) {
  throw new Error("V3 approval cannot use V2 state");
}
const config = configSchema.parse({
  ...base,
  server: {
    ...base.server,
    host: "127.0.0.1",
    port: 7344,
    publicUrl: publicUrl.origin,
    allowedHosts: ["127.0.0.1", "localhost", publicUrl.hostname],
  },
  auth: { ...base.auth, mode: "internal" },
  storage: { directory: path.join(stateRoot, "oauth") },
  audit: { ...base.audit, directory: path.join(stateRoot, "audit") },
});
const store = new Store(config.storage.directory);
try {
  const auth = new AuthService(config, store);
  await auth.initialize();
  const approved = auth.approve(approvalId);
  if (!approved) throw new Error("V3 OAuth request was not found or cannot be approved");
  process.stdout.write(
    JSON.stringify({
      approval: "OWNER_EXPLICIT_APPROVAL_RECORDED",
      requestId: approvalId,
      issuer: publicUrl.origin,
      v2StoreTouched: false,
    }) + "\n",
  );
} finally {
  store.close();
}
