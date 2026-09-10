import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";

import express, { type Express, type Request, type Response } from "express";
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter,
  type OAuthTokenVerifier,
} from "@modelcontextprotocol/express";
import {
  type AuthInfo,
  OAuthError,
  OAuthErrorCode,
  type OAuthMetadata,
} from "@modelcontextprotocol/server";
import {
  createRemoteJWKSet,
  decodeJwt,
  exportJWK,
  jwtVerify,
  SignJWT,
  type JWSAlgorithm,
  type JWK,
  type JWTVerifyOptions,
} from "jose";
import * as z from "zod/v4";

import type { AppConfig } from "../config/schema.js";
import { AppError } from "../errors.js";
import type { Store } from "../persistence/store.js";
import { canonicalJson, sha256 } from "../utils/json.js";
import { SERVER_VERSION } from "../version.js";
import { protectBytes, unprotectBytes } from "./dpapi.js";

const ALL_SCOPES = [
  "device:read",
  "filesystem:read",
  "filesystem:write",
  "process:read",
  "process:execute",
  "admin",
  "offline_access",
] as const;

const clientSchema = z.strictObject({
  redirect_uris: z.array(z.url()).min(1).max(16),
  client_name: z.string().min(1).max(200).optional(),
  client_uri: z.url().optional(),
  application_type: z.enum(["web", "native"]).default("web"),
  grant_types: z.array(z.string()).max(8).optional(),
  response_types: z.array(z.string()).max(8).optional(),
  token_endpoint_auth_method: z.literal("none").optional(),
});

type ClientMetadata = z.infer<typeof clientSchema>;
type ApprovalRow = {
  id: string;
  client_id: string;
  redirect_uri: string;
  challenge: string;
  scope: string;
  resource: string;
  state: string | null;
  subject: string | null;
  approved: number;
  expires_at: number;
};
type CodeRow = {
  client_id: string;
  redirect_uri: string;
  challenge: string;
  scope: string;
  resource: string;
  subject: string;
  expires_at: number;
};
type RefreshRow = {
  client_id: string;
  scope: string;
  resource: string;
  subject: string;
  expires_at: number;
  consumed_at: number | null;
  replacement_protected: string | null;
  replacement_expires_at: number | null;
};
type GeneratedTokenSet = {
  tokens: TokenSet;
  refreshHash: string;
  refreshExpiresAt: number;
};
type TokenSet = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
};
type RefreshRotationResult =
  { ok: true; tokens: TokenSet; replayed: boolean } | { ok: false; description: string };
type OauthEventInput = {
  clientHash: string;
  grantType: string;
  status: "success" | "error";
  latencyMs: number;
  errorCode: string | null;
};
type OwnerEnrollmentRow = {
  enrollment_id: string;
  client_id: string;
  redirect_uri: string;
  resource: string;
  scope: string;
  subject: string;
  created_at: number;
  last_used_at: number;
  revoked_at: number | null;
};
type AuthorizationGrant = {
  clientId: string;
  redirectUri: string;
  challenge: string;
  scope: string;
  resource: string;
  state: string | null;
  subject: string;
};

const INVALID_REFRESH_DESCRIPTION = "refresh token is invalid, expired, replayed, or mismatched";

function html(value: string): string {
  return value.replace(
    /[&<>"']/gu,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ??
      character,
  );
}

function oauthError(response: Response, status: number, error: string, description: string): void {
  response.locals["oauthErrorCode"] = error;
  response.status(status).json({ error, error_description: description });
}

function stringValue(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

export class AuthService implements OAuthTokenVerifier {
  private privateKey: ReturnType<typeof createPrivateKey> | undefined;
  private publicKey: ReturnType<typeof createPublicKey> | undefined;
  private publicJwk: JWK | undefined;
  private keyId = "";
  private remoteJwks: ReturnType<typeof createRemoteJWKSet> | undefined;
  private oauthMetadataValue: OAuthMetadata | undefined;
  private readonly refreshInFlight = new Map<string, Promise<RefreshRotationResult>>();

  readonly issuer: string;
  readonly resourceUrl: URL;

  constructor(
    private readonly config: AppConfig,
    private readonly store: Store,
  ) {
    const base = new URL(config.server.publicUrl);
    this.issuer = base.origin;
    this.resourceUrl = new URL("/mcp", `${base.origin}/`);
  }

  async initialize(): Promise<void> {
    if (this.config.auth.mode === "internal") {
      await this.initializeInternalKey();
      this.oauthMetadataValue = this.internalMetadata();
      return;
    }
    const issuer = this.config.auth.externalIssuer;
    const jwks = this.config.auth.externalJwksUrl;
    if (!issuer || !jwks)
      throw new AppError("INVALID_INPUT", "external issuer configuration is incomplete");
    this.remoteJwks = createRemoteJWKSet(new URL(jwks), {
      timeoutDuration: 5000,
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60_000,
    });
    const metadataUrl = new URL(issuer);
    const issuerPath = metadataUrl.pathname === "/" ? "" : metadataUrl.pathname.replace(/\/$/u, "");
    metadataUrl.pathname = `/.well-known/oauth-authorization-server${issuerPath}`;
    metadataUrl.search = "";
    metadataUrl.hash = "";
    const response = await fetch(metadataUrl, { signal: AbortSignal.timeout(5000) });
    if (!response.ok)
      throw new AppError("INTERNAL_ERROR", "external authorization metadata is unavailable");
    this.oauthMetadataValue = (await response.json()) as OAuthMetadata;
    if (this.oauthMetadataValue.issuer !== issuer)
      throw new AppError("INTERNAL_ERROR", "external authorization issuer mismatch");
  }

  install(app: Express): void {
    const metadata = this.oauthMetadata();
    const localInsecure =
      this.resourceUrl.protocol === "http:" &&
      ["127.0.0.1", "localhost", "::1"].includes(this.resourceUrl.hostname);
    app.use(
      mcpAuthMetadataRouter({
        oauthMetadata: metadata,
        resourceServerUrl: this.resourceUrl,
        ...(localInsecure ? { dangerouslyAllowInsecureIssuerUrl: true } : {}),
      }),
    );
    app.get("/auth-health", (_request, response) => {
      response.setHeader("cache-control", "no-store");
      response.json(this.health());
    });
    if (this.config.auth.mode !== "internal") return;
    app.use(express.urlencoded({ extended: false, limit: "32kb" }));
    app.get("/jwks", (_request, response) => response.json({ keys: [this.publicJwk] }));
    app.post("/register", (request, response) => this.registerClient(request, response));
    app.get("/authorize", (request, response) => void this.authorize(request, response));
    app.post("/token", (request, response) => void this.token(request, response));
    app.post("/revoke", (request, response) => this.revoke(request, response));
  }

  oauthMetadata(): OAuthMetadata {
    if (!this.oauthMetadataValue)
      throw new AppError("INTERNAL_ERROR", "authorization service is not initialized");
    return this.oauthMetadataValue;
  }

  resourceMetadataUrl(): string {
    return getOAuthProtectedResourceMetadataUrl(this.resourceUrl);
  }

  health(): {
    status: "healthy" | "unhealthy";
    mode: AppConfig["auth"]["mode"];
    signingReady: boolean;
    tokenEndpointReady: boolean;
    version: string;
  } {
    const signingReady =
      this.config.auth.mode === "internal"
        ? Boolean(this.privateKey && this.publicKey && this.publicJwk)
        : Boolean(this.remoteJwks);
    return {
      status:
        signingReady && Boolean(this.oauthMetadataValue?.token_endpoint) ? "healthy" : "unhealthy",
      mode: this.config.auth.mode,
      signingReady,
      tokenEndpointReady: Boolean(this.oauthMetadataValue?.token_endpoint),
      version: SERVER_VERSION,
    };
  }

  reconcileExpiredState(): { approvals: number; codes: number; refreshTokens: number } {
    const now = Date.now();
    const approvals = this.store.db
      .prepare("DELETE FROM oauth_approvals WHERE expires_at<=?")
      .run(now);
    const codes = this.store.db.prepare("DELETE FROM oauth_codes WHERE expires_at<=?").run(now);
    const refreshTokens = this.store.db
      .prepare(
        "DELETE FROM oauth_refresh WHERE (consumed_at IS NULL AND expires_at<=?) OR (consumed_at IS NOT NULL AND COALESCE(replacement_expires_at,consumed_at)<=?)",
      )
      .run(now, now);
    return {
      approvals: Number(approvals.changes),
      codes: Number(codes.changes),
      refreshTokens: Number(refreshTokens.changes),
    };
  }

  recentOauthEvents(limit = 50): unknown[] {
    const bounded = Math.min(Math.max(Math.trunc(limit), 1), 200);
    return this.store.db
      .prepare(
        "SELECT event_id,created_at,client_hash,grant_type,status,latency_ms,error_code FROM oauth_events ORDER BY created_at DESC,event_id DESC LIMIT ?",
      )
      .all(bounded);
  }

  ownerTrustEnrollments(limit = 100): unknown[] {
    const bounded = Math.min(Math.max(Math.trunc(limit), 1), 500);
    const rows = this.store.db
      .prepare(
        "SELECT enrollment_id,client_id,redirect_uri,resource,scope,subject,created_at,last_used_at,revoked_at FROM oauth_owner_enrollments ORDER BY created_at DESC LIMIT ?",
      )
      .all(bounded) as OwnerEnrollmentRow[];
    return rows.map((row) => ({
      enrollmentId: row.enrollment_id,
      clientHash: sha256(row.client_id).slice(0, 24),
      redirectUri: row.redirect_uri,
      resource: row.resource,
      scopes: row.scope.split(" ").filter(Boolean),
      subject: row.subject,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      active: row.revoked_at === null,
      revokedAt: row.revoked_at,
    }));
  }

  revokeOwnerEnrollment(enrollmentId: string): boolean {
    const enrollment = this.store.db
      .prepare(
        "SELECT enrollment_id,client_id,redirect_uri,resource,scope,subject,created_at,last_used_at,revoked_at FROM oauth_owner_enrollments WHERE enrollment_id=?",
      )
      .get(enrollmentId) as OwnerEnrollmentRow | undefined;
    if (!enrollment || enrollment.revoked_at !== null) return false;
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      const revoked = this.store.db
        .prepare(
          "UPDATE oauth_owner_enrollments SET revoked_at=? WHERE enrollment_id=? AND revoked_at IS NULL",
        )
        .run(Date.now(), enrollmentId);
      if (Number(revoked.changes) !== 1) {
        this.store.db.exec("ROLLBACK");
        return false;
      }
      this.store.db
        .prepare("DELETE FROM oauth_refresh WHERE client_id=? AND resource=?")
        .run(enrollment.client_id, enrollment.resource);
      this.store.db.prepare("DELETE FROM oauth_codes WHERE client_id=?").run(enrollment.client_id);
      this.store.db
        .prepare("DELETE FROM oauth_approvals WHERE client_id=?")
        .run(enrollment.client_id);
      this.store.db.exec("COMMIT");
      return true;
    } catch (error) {
      this.store.db.exec("ROLLBACK");
      throw error;
    }
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const expectedIssuer =
        this.config.auth.mode === "internal" ? this.issuer : this.config.auth.externalIssuer;
      if (!expectedIssuer) throw new Error("verification issuer unavailable");
      const verifyOptions: JWTVerifyOptions = {
        issuer: expectedIssuer,
        audience: this.resourceUrl.href,
        clockTolerance: 5,
        algorithms: ["ES256", "RS256"] satisfies JWSAlgorithm[],
      };
      let verified;
      if (this.config.auth.mode === "internal") {
        if (!this.publicKey) throw new Error("internal verification key unavailable");
        verified = await jwtVerify(token, this.publicKey, verifyOptions);
      } else {
        if (!this.remoteJwks) throw new Error("external verification key unavailable");
        verified = await jwtVerify(token, this.remoteJwks, verifyOptions);
      }
      const { payload } = verified;
      if (typeof payload.sub !== "string" || typeof payload.exp !== "number")
        throw new Error("required claims missing");
      if (typeof payload.jti === "string" && this.store.get(`oauth:revoked:${payload.jti}`))
        throw new Error("token revoked");
      const clientId =
        typeof payload["client_id"] === "string"
          ? payload["client_id"]
          : typeof payload["azp"] === "string"
            ? payload["azp"]
            : "";
      if (!clientId) throw new Error("client identifier missing");
      const scopes =
        typeof payload["scope"] === "string" ? payload["scope"].split(" ").filter(Boolean) : [];
      return {
        token,
        clientId,
        scopes,
        expiresAt: payload.exp,
        resource: this.resourceUrl,
        extra: { sub: payload.sub, jti: payload.jti },
      };
    } catch {
      throw new OAuthError(OAuthErrorCode.InvalidToken, "invalid or expired access token");
    }
  }

  approve(id: string, subject = `${os.hostname()}\\${os.userInfo().username}`): boolean {
    const result = this.store.db
      .prepare(
        "UPDATE oauth_approvals SET approved=1,subject=? WHERE id=? AND approved=0 AND expires_at>?",
      )
      .run(subject, id, Date.now());
    return result.changes === 1;
  }

  private async initializeInternalKey(): Promise<void> {
    const keyPath = path.join(this.config.storage.directory, "oauth-signing-key.dpapi");
    let privatePem: string;
    try {
      privatePem = (await unprotectBytes((await readFile(keyPath, "utf8")).trim())).toString(
        "utf8",
      );
      this.privateKey = createPrivateKey(privatePem);
      this.publicKey = createPublicKey(this.privateKey);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
      this.privateKey = pair.privateKey;
      this.publicKey = pair.publicKey;
      privatePem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
      await writeFile(keyPath, await protectBytes(Buffer.from(privatePem)), {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
    }
    const jwk = await exportJWK(this.publicKey);
    this.keyId = sha256(canonicalJson(jwk)).slice(0, 24);
    this.publicJwk = { ...jwk, kid: this.keyId, use: "sig", alg: "ES256" };
  }

  private internalMetadata(): OAuthMetadata {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/authorize`,
      token_endpoint: `${this.issuer}/token`,
      registration_endpoint: `${this.issuer}/register`,
      revocation_endpoint: `${this.issuer}/revoke`,
      jwks_uri: `${this.issuer}/jwks`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: [...ALL_SCOPES],
    };
  }

  private registerClient(request: Request, response: Response): void {
    const parsed = clientSchema.safeParse(request.body);
    if (!parsed.success || parsed.data.redirect_uris.some((uri) => !this.redirectAllowed(uri))) {
      oauthError(response, 400, "invalid_redirect_uri", "redirect URI is invalid or not allowed");
      return;
    }
    const clientId = `radlina-${randomUUID()}`;
    const metadata: ClientMetadata = parsed.data;
    this.store.db
      .prepare("INSERT INTO oauth_clients(client_id,metadata_json,created_at) VALUES(?,?,?)")
      .run(clientId, JSON.stringify(metadata), Date.now());
    response
      .status(201)
      .json({ ...metadata, client_id: clientId, token_endpoint_auth_method: "none" });
  }

  private async authorize(request: Request, response: Response): Promise<void> {
    this.cleanupOauth();
    const requestId =
      typeof request.query["request_id"] === "string" ? request.query["request_id"] : undefined;
    if (requestId) {
      const approval = this.store.db
        .prepare("SELECT * FROM oauth_approvals WHERE id=?")
        .get(requestId) as ApprovalRow | undefined;
      if (!approval || approval.expires_at <= Date.now()) {
        oauthError(response, 400, "invalid_request", "approval request is missing or expired");
        return;
      }
      if (!approval.approved || !approval.subject) {
        this.renderApproval(response, approval.id, approval.client_id, approval.scope, false);
        return;
      }
      this.issueAuthorizationRedirect(
        response,
        {
          clientId: approval.client_id,
          redirectUri: approval.redirect_uri,
          challenge: approval.challenge,
          scope: approval.scope,
          resource: approval.resource,
          state: approval.state,
          subject: approval.subject,
        },
        { approvalId: approval.id, enrollOwner: true },
      );
      return;
    }

    const clientId = stringValue(request.query["client_id"]);
    const redirectUri = stringValue(request.query["redirect_uri"]);
    const challenge = stringValue(request.query["code_challenge"]);
    const challengeMethod = stringValue(request.query["code_challenge_method"]);
    const resource = stringValue(request.query["resource"]);
    const scope = stringValue(request.query["scope"], "device:read filesystem:read");
    const state = typeof request.query["state"] === "string" ? request.query["state"] : null;
    if (
      request.query["response_type"] !== "code" ||
      challengeMethod !== "S256" ||
      challenge.length < 43
    ) {
      oauthError(response, 400, "invalid_request", "authorization code with PKCE S256 is required");
      return;
    }
    if (resource !== this.resourceUrl.href) {
      oauthError(
        response,
        400,
        "invalid_target",
        "resource must match the canonical MCP resource URL",
      );
      return;
    }
    const client = this.client(clientId);
    if (!client || !client.redirect_uris.includes(redirectUri)) {
      oauthError(
        response,
        400,
        "invalid_request",
        "client or exact redirect URI is not registered",
      );
      return;
    }
    const scopes = [...new Set(scope.split(" ").filter(Boolean))];
    if (
      scopes.length === 0 ||
      scopes.some((item) => !ALL_SCOPES.includes(item as (typeof ALL_SCOPES)[number]))
    ) {
      oauthError(response, 400, "invalid_scope", "one or more requested scopes are not supported");
      return;
    }
    const normalizedScope = scopes.join(" ");
    const enrollment = this.activeOwnerEnrollment(clientId, redirectUri, resource, scopes);
    if (enrollment) {
      this.issueAuthorizationRedirect(
        response,
        {
          clientId,
          redirectUri,
          challenge,
          scope: normalizedScope,
          resource,
          state,
          subject: enrollment.subject,
        },
        { enrollmentId: enrollment.enrollment_id },
      );
      return;
    }
    const id = randomUUID();
    this.store.db
      .prepare(
        "INSERT INTO oauth_approvals(id,client_id,redirect_uri,challenge,scope,resource,state,expires_at) VALUES(?,?,?,?,?,?,?,?)",
      )
      .run(
        id,
        clientId,
        redirectUri,
        challenge,
        normalizedScope,
        resource,
        state,
        Date.now() + 10 * 60_000,
      );
    this.renderApproval(response, id, clientId, normalizedScope, false);
  }

  private activeOwnerEnrollment(
    clientId: string,
    redirectUri: string,
    resource: string,
    scopes: string[],
  ): OwnerEnrollmentRow | undefined {
    const enrollment = this.store.db
      .prepare(
        "SELECT enrollment_id,client_id,redirect_uri,resource,scope,subject,created_at,last_used_at,revoked_at FROM oauth_owner_enrollments WHERE client_id=? AND redirect_uri=? AND resource=? AND revoked_at IS NULL",
      )
      .get(clientId, redirectUri, resource) as OwnerEnrollmentRow | undefined;
    if (!enrollment) return undefined;
    const approvedScopes = new Set(enrollment.scope.split(" ").filter(Boolean));
    return scopes.every((requested) => approvedScopes.has(requested)) ? enrollment : undefined;
  }

  private issueAuthorizationRedirect(
    response: Response,
    grant: AuthorizationGrant,
    options: { approvalId?: string; enrollOwner?: boolean; enrollmentId?: string },
  ): void {
    const rawCode = randomBytes(32).toString("base64url");
    const now = Date.now();
    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      if (options.approvalId) {
        const consumed = this.store.db
          .prepare("DELETE FROM oauth_approvals WHERE id=? AND approved=1")
          .run(options.approvalId);
        if (Number(consumed.changes) !== 1)
          throw new AppError("CONFLICT", "approval request was already consumed");
      }
      if (options.enrollOwner) {
        this.store.db
          .prepare(
            `INSERT INTO oauth_owner_enrollments(
              enrollment_id,client_id,redirect_uri,resource,scope,subject,created_at,last_used_at,revoked_at
            ) VALUES(?,?,?,?,?,?,?,?,NULL)
            ON CONFLICT(client_id,redirect_uri,resource) DO UPDATE SET
              scope=excluded.scope,subject=excluded.subject,last_used_at=excluded.last_used_at,revoked_at=NULL`,
          )
          .run(
            randomUUID(),
            grant.clientId,
            grant.redirectUri,
            grant.resource,
            grant.scope,
            grant.subject,
            now,
            now,
          );
      } else if (options.enrollmentId) {
        const touched = this.store.db
          .prepare(
            "UPDATE oauth_owner_enrollments SET last_used_at=? WHERE enrollment_id=? AND revoked_at IS NULL",
          )
          .run(now, options.enrollmentId);
        if (Number(touched.changes) !== 1)
          throw new AppError("CONFLICT", "owner enrollment is no longer active");
      }
      this.store.db
        .prepare(
          "INSERT INTO oauth_codes(code_hash,client_id,redirect_uri,challenge,scope,resource,subject,expires_at) VALUES(?,?,?,?,?,?,?,?)",
        )
        .run(
          sha256(rawCode),
          grant.clientId,
          grant.redirectUri,
          grant.challenge,
          grant.scope,
          grant.resource,
          grant.subject,
          now + 120_000,
        );
      this.store.db.exec("COMMIT");
    } catch (error) {
      this.store.db.exec("ROLLBACK");
      throw error;
    }
    const redirect = new URL(grant.redirectUri);
    redirect.searchParams.set("code", rawCode);
    if (grant.state) redirect.searchParams.set("state", grant.state);
    response.setHeader("cache-control", "no-store");
    response.redirect(302, redirect.href);
  }

  private renderApproval(
    response: Response,
    id: string,
    clientId: string,
    scope: string,
    approved: boolean,
  ): void {
    response.setHeader("cache-control", "no-store");
    response
      .type("html")
      .send(
        `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Radlina authorization</title></head><body><main><h1>Radlina Remote MCP authorization</h1><p>Client: <code>${html(clientId)}</code></p><p>Requested scopes: <code>${html(scope)}</code></p><p>Request ID: <code>${html(id)}</code></p><p>On LAPTOP-13QINEIF run:</p><pre>npm run control -- approve ${html(id)}</pre><p>${approved ? "Approved." : "After approving locally, refresh this page."}</p><p><a href="/authorize?request_id=${encodeURIComponent(id)}">Refresh status</a></p></main></body></html>`,
      );
  }

  private async token(request: Request, response: Response): Promise<void> {
    this.cleanupOauth();
    const started = performance.now();
    const body = request.body as Record<string, unknown>;
    const requestedGrantType = stringValue(body["grant_type"], "unknown");
    const grantType = ["authorization_code", "refresh_token"].includes(requestedGrantType)
      ? requestedGrantType
      : "unknown";
    const clientId = stringValue(body["client_id"]);
    const clientHash = clientId ? sha256(clientId).slice(0, 24) : "none";
    response.once("finish", () => {
      const errorCode =
        typeof response.locals["oauthErrorCode"] === "string"
          ? response.locals["oauthErrorCode"]
          : null;
      this.recordOauthEvent({
        clientHash,
        grantType,
        status: response.statusCode >= 200 && response.statusCode < 400 ? "success" : "error",
        latencyMs: Math.max(0, Math.round(performance.now() - started)),
        errorCode,
      });
    });
    if (grantType === "authorization_code") {
      const rawCode = stringValue(body["code"]);
      const codeHash = sha256(rawCode);
      const row = this.store.db
        .prepare("SELECT * FROM oauth_codes WHERE code_hash=?")
        .get(codeHash) as CodeRow | undefined;
      const verifier = stringValue(body["code_verifier"]);
      const challenge = Buffer.from(
        await crypto.subtle.digest("SHA-256", Buffer.from(verifier)),
      ).toString("base64url");
      if (
        !row ||
        row.expires_at <= Date.now() ||
        row.client_id !== clientId ||
        row.redirect_uri !== stringValue(body["redirect_uri"]) ||
        row.resource !== stringValue(body["resource"]) ||
        challenge !== row.challenge
      ) {
        oauthError(
          response,
          400,
          "invalid_grant",
          "authorization code is invalid, expired, replayed, or PKCE validation failed",
        );
        return;
      }
      const consumed = this.store.db
        .prepare("DELETE FROM oauth_codes WHERE code_hash=?")
        .run(codeHash);
      if (Number(consumed.changes) !== 1) {
        oauthError(response, 400, "invalid_grant", "authorization code was already consumed");
        return;
      }
      response.setHeader("cache-control", "no-store");
      response.json(await this.issueTokens(row.client_id, row.subject, row.scope, row.resource));
      return;
    }
    if (grantType === "refresh_token") {
      const rotated = await this.rotateRefreshToken(
        stringValue(body["refresh_token"]),
        clientId,
        stringValue(body["resource"]),
      );
      if (!rotated.ok) {
        oauthError(response, 400, "invalid_grant", rotated.description);
        return;
      }
      response.setHeader("cache-control", "no-store");
      response.json(rotated.tokens);
      return;
    }
    oauthError(
      response,
      400,
      "unsupported_grant_type",
      "supported grants are authorization_code and refresh_token",
    );
  }

  private async issueTokens(
    clientId: string,
    subject: string,
    scope: string,
    resource: string,
  ): Promise<TokenSet> {
    const generated = await this.generateTokenSet(clientId, subject, scope, resource);
    this.store.db
      .prepare(
        "INSERT INTO oauth_refresh(token_hash,client_id,scope,resource,subject,expires_at) VALUES(?,?,?,?,?,?)",
      )
      .run(generated.refreshHash, clientId, scope, resource, subject, generated.refreshExpiresAt);
    return generated.tokens;
  }

  private async generateTokenSet(
    clientId: string,
    subject: string,
    scope: string,
    resource: string,
  ): Promise<GeneratedTokenSet> {
    if (!this.privateKey) throw new AppError("INTERNAL_ERROR", "internal signing key unavailable");
    const jti = randomUUID();
    const accessToken = await new SignJWT({ scope, client_id: clientId })
      .setProtectedHeader({ alg: "ES256", kid: this.keyId, typ: "JWT" })
      .setIssuer(this.issuer)
      .setSubject(subject)
      .setAudience(resource)
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime(`${this.config.auth.accessTokenTtlSeconds}s`)
      .sign(this.privateKey);
    const refreshToken = randomBytes(48).toString("base64url");
    return {
      tokens: {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: this.config.auth.accessTokenTtlSeconds,
        refresh_token: refreshToken,
        scope,
      },
      refreshHash: sha256(refreshToken),
      refreshExpiresAt: Date.now() + this.config.auth.refreshTokenTtlSeconds * 1000,
    };
  }

  private async rotateRefreshToken(
    rawToken: string,
    clientId: string,
    resource: string,
  ): Promise<RefreshRotationResult> {
    const tokenHash = sha256(rawToken);
    const initial = this.refreshRow(tokenHash);
    if (!this.refreshRequestValid(initial, clientId, resource, Date.now())) {
      return { ok: false, description: INVALID_REFRESH_DESCRIPTION };
    }

    const existing = this.refreshInFlight.get(tokenHash);
    if (existing) return await existing;

    const rotation = this.rotateRefreshTokenOnce(tokenHash, clientId, resource);
    this.refreshInFlight.set(tokenHash, rotation);
    try {
      return await rotation;
    } finally {
      if (this.refreshInFlight.get(tokenHash) === rotation) this.refreshInFlight.delete(tokenHash);
    }
  }

  private async rotateRefreshTokenOnce(
    tokenHash: string,
    clientId: string,
    resource: string,
  ): Promise<RefreshRotationResult> {
    const before = this.refreshRow(tokenHash);
    const beforeNow = Date.now();
    if (!this.refreshRequestValid(before, clientId, resource, beforeNow)) {
      return { ok: false, description: INVALID_REFRESH_DESCRIPTION };
    }
    if (before?.consumed_at !== null) return await this.replayRotation(before, beforeNow);

    const generated = await this.generateTokenSet(
      before.client_id,
      before.subject,
      before.scope,
      before.resource,
    );
    const protectedReceipt = await protectBytes(
      Buffer.from(JSON.stringify(generated.tokens), "utf8"),
    );
    const consumedAt = Date.now();
    const replayExpiresAt = consumedAt + this.config.auth.refreshReplayGraceSeconds * 1000;

    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      const current = this.refreshRow(tokenHash);
      if (!this.refreshRequestValid(current, clientId, resource, Date.now())) {
        this.store.db.exec("COMMIT");
        return { ok: false, description: INVALID_REFRESH_DESCRIPTION };
      }
      if (current.consumed_at !== null) {
        this.store.db.exec("COMMIT");
        return await this.replayRotation(current, Date.now());
      }
      const consumed = this.store.db
        .prepare(
          "UPDATE oauth_refresh SET consumed_at=?,replacement_protected=?,replacement_expires_at=? WHERE token_hash=? AND consumed_at IS NULL",
        )
        .run(consumedAt, protectedReceipt, replayExpiresAt, tokenHash);
      if (Number(consumed.changes) !== 1) {
        this.store.db.exec("ROLLBACK");
        const winner = this.refreshRow(tokenHash);
        return this.refreshRequestValid(winner, clientId, resource, Date.now()) &&
          winner?.consumed_at !== null
          ? await this.replayRotation(winner, Date.now())
          : { ok: false, description: INVALID_REFRESH_DESCRIPTION };
      }
      this.store.db
        .prepare(
          "INSERT INTO oauth_refresh(token_hash,client_id,scope,resource,subject,expires_at) VALUES(?,?,?,?,?,?)",
        )
        .run(
          generated.refreshHash,
          current.client_id,
          current.scope,
          current.resource,
          current.subject,
          generated.refreshExpiresAt,
        );
      this.store.db.exec("COMMIT");
      return { ok: true, tokens: generated.tokens, replayed: false };
    } catch (error) {
      try {
        this.store.db.exec("ROLLBACK");
      } catch {
        // Preserve the original error if SQLite already ended the transaction.
      }
      throw error;
    }
  }

  private refreshRow(tokenHash: string): RefreshRow | undefined {
    return this.store.db
      .prepare(
        "SELECT client_id,scope,resource,subject,expires_at,consumed_at,replacement_protected,replacement_expires_at FROM oauth_refresh WHERE token_hash=?",
      )
      .get(tokenHash) as RefreshRow | undefined;
  }

  private refreshRequestValid(
    row: RefreshRow | undefined,
    clientId: string,
    resource: string,
    now: number,
  ): row is RefreshRow {
    return Boolean(
      row && row.expires_at > now && row.client_id === clientId && row.resource === resource,
    );
  }

  private async replayRotation(row: RefreshRow, now: number): Promise<RefreshRotationResult> {
    if (
      row.consumed_at === null ||
      !row.replacement_protected ||
      row.replacement_expires_at === null ||
      row.replacement_expires_at <= now
    ) {
      return { ok: false, description: INVALID_REFRESH_DESCRIPTION };
    }
    const decoded = JSON.parse(
      (await unprotectBytes(row.replacement_protected)).toString("utf8"),
    ) as Partial<TokenSet>;
    if (
      typeof decoded.access_token !== "string" ||
      decoded.token_type !== "Bearer" ||
      typeof decoded.expires_in !== "number" ||
      typeof decoded.refresh_token !== "string" ||
      typeof decoded.scope !== "string"
    ) {
      throw new AppError("INTERNAL_ERROR", "OAuth refresh replay receipt is invalid");
    }
    return { ok: true, tokens: decoded as TokenSet, replayed: true };
  }

  private recordOauthEvent(event: OauthEventInput): void {
    try {
      this.store.db.exec("BEGIN IMMEDIATE");
      this.store.db
        .prepare(
          "INSERT INTO oauth_events(event_id,created_at,client_hash,grant_type,status,latency_ms,error_code) VALUES(?,?,?,?,?,?,?)",
        )
        .run(
          randomUUID(),
          Date.now(),
          event.clientHash.slice(0, 64),
          event.grantType.slice(0, 64),
          event.status,
          Math.min(Math.max(Math.trunc(event.latencyMs), 0), 2_147_483_647),
          event.errorCode?.slice(0, 64) ?? null,
        );
      this.store.db.exec(
        "DELETE FROM oauth_events WHERE event_id NOT IN (SELECT event_id FROM oauth_events ORDER BY created_at DESC,event_id DESC LIMIT 5000)",
      );
      this.store.db.exec("COMMIT");
    } catch {
      try {
        this.store.db.exec("ROLLBACK");
      } catch {
        // Telemetry is intentionally best effort and never affects token issuance.
      }
    }
  }

  private revoke(request: Request, response: Response): void {
    const token = stringValue((request.body as Record<string, unknown>)["token"]);
    if (token.includes(".")) {
      try {
        const payload = decodeJwt(token);
        if (typeof payload.jti === "string" && typeof payload.exp === "number") {
          this.store.set(`oauth:revoked:${payload.jti}`, String(payload.exp));
        }
      } catch {
        // RFC 7009 intentionally returns success for unknown tokens.
      }
    } else {
      this.store.db.prepare("DELETE FROM oauth_refresh WHERE token_hash=?").run(sha256(token));
    }
    response.status(200).end();
  }

  private client(clientId: string): ClientMetadata | undefined {
    const row = this.store.db
      .prepare("SELECT metadata_json FROM oauth_clients WHERE client_id=?")
      .get(clientId) as { metadata_json: string } | undefined;
    return row ? clientSchema.parse(JSON.parse(row.metadata_json) as unknown) : undefined;
  }

  private redirectAllowed(raw: string): boolean {
    try {
      const url = new URL(raw);
      if (url.username || url.password || url.hash) return false;
      const loopback = ["127.0.0.1", "localhost", "::1", "[::1]"].includes(url.hostname);
      if (loopback) return url.protocol === "http:" || url.protocol === "https:";
      if (url.protocol !== "https:") return false;
      return this.config.auth.allowedRedirectHosts.some(
        (host) => url.hostname === host || url.hostname.endsWith(`.${host}`),
      );
    } catch {
      return false;
    }
  }

  private cleanupOauth(): void {
    this.reconcileExpiredState();
  }
}
