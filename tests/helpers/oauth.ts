import { createHash } from "node:crypto";

import type { AuthService } from "../../src/auth/service.js";

export async function issueToken(
  base: string,
  auth: AuthService,
  scope = "device:read filesystem:read",
): Promise<string> {
  const registration = await fetch(`${base}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: ["http://127.0.0.1/callback"], client_name: "mcp-test" }),
  });
  const client = (await registration.json()) as { client_id: string };
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
  const authorize = new URL(`${base}/authorize`);
  authorize.search = new URLSearchParams({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: "http://127.0.0.1/callback",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    resource: auth.resourceUrl.href,
    scope,
  }).toString();
  const approvalHtml = await (await fetch(authorize)).text();
  const requestId = /Request ID: <code>([0-9a-f-]+)<\/code>/u.exec(approvalHtml)?.[1];
  if (!requestId || !auth.approve(requestId, "mcp-test-user")) throw new Error("approval failed");
  const redirect = await fetch(`${base}/authorize?request_id=${requestId}`, { redirect: "manual" });
  const code = new URL(redirect.headers.get("location") ?? "").searchParams.get("code");
  if (!code) throw new Error("authorization code missing");
  const token = await fetch(`${base}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: client.client_id,
      redirect_uri: "http://127.0.0.1/callback",
      code_verifier: verifier,
      resource: auth.resourceUrl.href,
    }),
  });
  const body = (await token.json()) as { access_token: string };
  return body.access_token;
}
