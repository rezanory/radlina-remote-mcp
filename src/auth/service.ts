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
import { protectBytes, unprotectBytes } from "./dpapi.js";

const ALL_SCOPES = [
  "device:read",
  "filesystem:read",
  "filesystem:write",
  "process:read",
  "process:execute",
  "admin",
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
};

function html(value: string): string {
  return value.replace(
    /[&<>"']/gu,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ??
      character,
  );
}

function oauthError(response: Response, status: number, error: string, description: string): void {
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
      this.store.db.prepare("DELETE FROM oauth_approvals WHERE id=?").run(approval.id);
      const rawCode = randomBytes(32).toString("base64url");
      this.store.db
        .prepare(
          "INSERT INTO oauth_codes(code_hash,client_id,redirect_uri,challenge,scope,resource,subject,expires_at) VALUES(?,?,?,?,?,?,?,?)",
        )
        .run(
          sha256(rawCode),
          approval.client_id,
          approval.redirect_uri,
          approval.challenge,
          approval.scope,
          approval.resource,
          approval.subject,
          Date.now() + 120_000,
        );
      const redirect = new URL(approval.redirect_uri);
      redirect.searchParams.set("code", rawCode);
      if (approval.state) redirect.searchParams.set("state", approval.state);
      response.redirect(302, redirect.href);
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
    const scopes = scope.split(" ").filter(Boolean);
    if (
      scopes.length === 0 ||
      scopes.some((item) => !ALL_SCOPES.includes(item as (typeof ALL_SCOPES)[number]))
    ) {
      oauthError(response, 400, "invalid_scope", "one or more requested scopes are not supported");
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
        scopes.join(" "),
        resource,
        state,
        Date.now() + 10 * 60_000,
      );
    this.renderApproval(response, id, clientId, scopes.join(" "), false);
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
    const body = request.body as Record<string, unknown>;
    const grantType = stringValue(body["grant_type"]);
    if (grantType === "authorization_code") {
      const rawCode = stringValue(body["code"]);
      const row = this.store.db
        .prepare("SELECT * FROM oauth_codes WHERE code_hash=?")
        .get(sha256(rawCode)) as CodeRow | undefined;
      this.store.db.prepare("DELETE FROM oauth_codes WHERE code_hash=?").run(sha256(rawCode));
      const verifier = stringValue(body["code_verifier"]);
      const challenge = Buffer.from(
        await crypto.subtle.digest("SHA-256", Buffer.from(verifier)),
      ).toString("base64url");
      if (
        !row ||
        row.expires_at <= Date.now() ||
        row.client_id !== stringValue(body["client_id"]) ||
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
      response.setHeader("cache-control", "no-store");
      response.json(await this.issueTokens(row.client_id, row.subject, row.scope, row.resource));
      return;
    }
    if (grantType === "refresh_token") {
      const raw = stringValue(body["refresh_token"]);
      const hash = sha256(raw);
      const row = this.store.db
        .prepare("SELECT * FROM oauth_refresh WHERE token_hash=?")
        .get(hash) as RefreshRow | undefined;
      this.store.db.prepare("DELETE FROM oauth_refresh WHERE token_hash=?").run(hash);
      if (
        !row ||
        row.expires_at <= Date.now() ||
        row.client_id !== stringValue(body["client_id"]) ||
        row.resource !== stringValue(body["resource"])
      ) {
        oauthError(
          response,
          400,
          "invalid_grant",
          "refresh token is invalid, expired, replayed, or for another resource",
        );
        return;
      }
      response.setHeader("cache-control", "no-store");
      response.json(await this.issueTokens(row.client_id, row.subject, row.scope, row.resource));
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
  ): Promise<Record<string, unknown>> {
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
    this.store.db
      .prepare(
        "INSERT INTO oauth_refresh(token_hash,client_id,scope,resource,subject,expires_at) VALUES(?,?,?,?,?,?)",
      )
      .run(
        sha256(refreshToken),
        clientId,
        scope,
        resource,
        subject,
        Date.now() + this.config.auth.refreshTokenTtlSeconds * 1000,
      );
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: this.config.auth.accessTokenTtlSeconds,
      refresh_token: refreshToken,
      scope,
    };
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
    const now = Date.now();
    this.store.db.prepare("DELETE FROM oauth_approvals WHERE expires_at<=?").run(now);
    this.store.db.prepare("DELETE FROM oauth_codes WHERE expires_at<=?").run(now);
    this.store.db.prepare("DELETE FROM oauth_refresh WHERE expires_at<=?").run(now);
  }
}
