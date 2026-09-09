# Radlina Remote MCP

## Value Proposition

Provide Reza Nouri with a self-hosted, local-first, production-quality MCP service on the Windows laptop `LAPTOP-13QINEIF`, reachable by ChatGPT and compatible MCP clients through a narrowly exposed HTTPS path carried by Tailscale.

The current gap is the absence of a secure, persistent, auditable remote control surface for approved device, filesystem, search, process, configuration, and diagnostic actions. The service must be fast, resilient, recoverable, default-deny, and must never expose anonymous command execution.

Core actions:

1. Inspect device health and approved filesystem/workspace content.
2. Perform explicitly scoped, idempotent filesystem and process actions.
3. Maintain reconnectable process/search sessions with policy and audit visibility.

## Why an LLM Client

- Conversational win: the user can state an operational intent while the client chooses a small, typed tool and supplies structured arguments.
- LLM contribution: intent parsing, safe sequencing, result summarization, and recovery decisions across multiple narrowly scoped tools.
- Required server contribution: authoritative authorization, policy enforcement, canonical path validation, real device state, process/session persistence, and auditable execution. The model is never the security boundary.

## Client Experience

This is a tool-first MCP server without custom UI.

1. The client initializes a Streamable HTTP session and discovers annotated tools.
2. The user starts with health, identity, capability, and read-only operations.
3. Mutation and process tools require narrower OAuth scopes, policy approval, idempotency metadata, and explicit safety annotations.
4. Search and process jobs return durable identifiers and deterministic cursors for reconnectable reads.
5. The experience concludes with a structured result, correlation ID, policy decision, and sanitized audit record.

## UX Flows

All flows are tool-only; no custom view is required.

1. Inspect: initialize, authenticate, check health/capabilities, then list/read approved content or process state.
2. Search: start a bounded search job, poll status, page deterministic results, and optionally cancel it.
3. Mutate files: simulate policy, execute an idempotent create/write/edit/copy/move request, then return verification metadata.
4. Run a process: simulate policy, start an allowlisted executable with structured arguments, reconnect using the session ID, page output by cursor, interact, and terminate.
5. Operate: inspect effective configuration and sanitized diagnostics, validate proposed configuration, enable emergency read-only mode or activate the kill switch locally.

## MCP Tool API

Device tools:

- `who_am_i`, `list_devices`, `ping`, `get_capabilities`, `health`, `version`.

Filesystem tools:

- `list_directory`, `read_file`, `read_multiple_files`, `get_file_info`.
- `create_directory`, `write_file`, `edit_block`, `copy`, `move`.
- `trash` exists only when the active profile enables recoverable deletion and the caller has `admin` plus explicit confirmation metadata.

Search tools:

- `start_search`, `search_status`, `search_results`, `cancel_search`.

Process tools:

- `list_processes`, `start_process`, `read_process_output`, `interact_with_process`, `terminate_process`.

Configuration and diagnostics tools:

- `get_effective_config`, `validate_config`, `simulate_policy`, `recent_tool_calls`, `active_sessions`, `resource_stats`, `readiness`, `error_details`.

Every mutation accepts `idempotencyKey`. Every job/session result includes a stable identifier. Paginated operations use deterministic opaque cursors. Tools carry accurate read-only, destructive, and open-world annotations.

## Product Context

- Primary client: ChatGPT MCP connection in developer mode.
- Secondary clients: Codex, VS Code/Cursor, MCP Inspector, and standards-compliant MCP clients.
- Runtime: supported Node.js LTS with TypeScript and the official MCP TypeScript SDK.
- Host: Windows 11 Home, non-administrator interactive user by default.
- Exposure: loopback application listener; Tailscale Funnel only for the minimum public HTTPS MCP route when required by ChatGPT. Tailscale Serve remains the private alternative.
- Authentication: OAuth 2.1-compatible discovery and protected-resource metadata; short-lived, audience-bound, scope-bearing tokens. The server supports a local development issuer while allowing a production issuer/JWKS configuration.
- Persistence: SQLite only for durable jobs, idempotency, replay prevention, and audit metadata.
- Allowed roots: project root only by default. Additional roots require explicit profile configuration.
- Deletion: disabled by default; optional recoverable quarantine requires an administrative scope and confirmation metadata.
- Secrets: never stored in the repository; production secrets use Windows DPAPI/Credential Manager or an external compliant issuer.

## Protocol and Compatibility Contract

- MCP specification baseline: `2026-07-28`, with compatibility for `2025-11-25` and `2025-06-18` clients where supported by the SDK.
- Transport: Streamable HTTP at `/mcp`; no legacy HTTP+SSE endpoint unless a verified client requires it.
- HTTP endpoint requires bearer authorization on every MCP request.
- Invalid `Origin` or `Host` is rejected before MCP dispatch.
- OAuth protected-resource metadata is served at both root and path-aware well-known locations.
- OAuth issuer metadata exposes authorization code + PKCE, refresh-token rotation, revocation, JWKS, and dynamic registration for compatibility. Production can delegate token issuance to a configured external issuer.
- Scopes: `device:read`, `filesystem:read`, `filesystem:write`, `process:read`, `process:execute`, and `admin`.
- Tool errors are typed, stable, sanitized, and include correlation IDs.

## Security and Operational Decisions

- Default deny for tools, paths, commands, origins, hosts, and scopes.
- Structured executable/argument process launches; shell invocation is opt-in and separately policy-gated.
- Canonical paths are checked on request and rechecked immediately before mutation.
- UNC, device paths, NTFS alternate data streams, junction/symlink escapes, and reserved device names are rejected unless a future reviewed profile explicitly permits them.
- Bounded request bodies, file sizes, output, runtime, concurrency, sessions, rate, and queues.
- Tamper-evident audit chain using HMAC-SHA-256 over canonical records; redaction occurs before persistence.
- Mutations require idempotency keys and return cached results for safe retries.
- Emergency read-only mode and a local kill switch are available without uninstalling.
- Tailscale/public exposure and Windows persistence are applied only after local validation succeeds and are fully reversible.

## Acceptance Scope

Implementation, tests, scripts, threat model, ADRs, capability matrix, SBOM, dependency and secret scans, benchmarks, sanitized evidence, installation/rollback instructions, and the final acceptance report are required. ChatGPT UI confirmation, Tailscale web consent, administrator elevation, and externally issued production credentials may be the only user-interactive blockers.
