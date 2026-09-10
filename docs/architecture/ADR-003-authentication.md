# ADR-003: OAuth and bearer-token architecture

Status: Accepted

## Decision

Implement the MCP server as an OAuth protected resource and provide two issuer modes:

1. `internal`: a self-hosted OAuth 2.1-compatible authorization server using authorization code + PKCE, one-time local owner enrollment bound to an exact registered client/redirect/resource/scope relationship, `offline_access`, retry-safe rotating refresh tokens, audience-bound signed access tokens, revocation, protected-resource metadata, authorization-server metadata, JWKS, and dynamic client registration for current client compatibility.
2. `external`: validate signed JWTs from a configured issuer/JWKS while keeping the same protected-resource metadata and per-tool scopes.

The internal issuer never accepts a password or pairing secret through chat. For a new relationship the browser displays a non-secret request identifier; the user approves that exact request through the local control CLI. A later request is automatic only when the registered client, exact redirect URI, resource, and requested scope subset match an active enrollment. Authorization codes are delivered only to the registered redirect URI, and the enrollment can be revoked locally.

## Security properties

- Authorization is enforced before MCP dispatch.
- Every tool independently checks required scopes.
- Access tokens are short-lived and bound to the canonical MCP resource URI.
- Authorization codes, pairing codes, refresh tokens, and replay keys are stored only as hashes.
- Signing and audit keys are encrypted with Windows DPAPI for the local machine and protected by a restricted project ACL so LocalSystem and the local operator can use the same durable state.
