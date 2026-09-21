# ADR-004: V2 component-first Smart Operator

- Status: Accepted
- Date: 2026-09-11
- Generation: Radlina V2
- Baseline: Golden V1 `75a13f06d66c0979260b574c546119f4dc8e80b7`

## Context

Golden V1 is an immutable recovery build. V2 must evolve on an independent release line while preserving V1 security boundaries, exact-SHA release evidence, OAuth policy enforcement, idempotency, durable SQLite state, and auditability.

The long-term architecture requires a small core and independently versionable components. ChatSentinel remains an independent product and may consume Radlina through a separately versioned bridge; it is not part of Radlina Core.

## Decision

V2 introduces a `CapabilityRegistry`. Components register typed capability providers. Capability IDs, ownership, version, scope, risk, read-only state, and idempotency are explicit metadata. Duplicate capability ownership fails closed before partial registration. Components can be registered and unregistered independently; persistent enable/disable packaging is a subsequent V2 milestone.

V2 also introduces a deterministic `OperatorManager`. Natural-language planning stays in the MCP client/agent. The server remains the security boundary and executes only structured plans containing registered capability IDs and bounded inputs.

Operator plans are persisted before execution. Every remaining step is policy-preflighted. Step receipts, attempts, timestamps, cancellation requests, and job state are durable in SQLite. Structured step inputs, results, and errors are protected with Windows DPAPI `LocalMachine` before persistence; an input SHA-256 receipt is stored and verified after decrypt but before capability execution. Radlina never falls back to plaintext persistence if payload protection fails.

Automatic retry is allowed only for capabilities that declare `idempotent=true`. Non-idempotent capabilities such as `process.exec` must use `maxAttempts=1`. After a service restart, in-flight steps become `interrupted`; an interrupted or failed non-idempotent step is never replayed automatically because its external outcome may be unknown.

The initial built-in component adapters are:

- `device.health`
- `filesystem.info`
- `process.exec`

The existing V1 MCP tools remain available for compatibility. V2 operator execution resolves capabilities through the registry, establishing the migration path from direct tool wiring to component providers without a flag-day rewrite.

## Dependency and reuse review

No new runtime dependency is added in this milestone.

The following public implementations were reviewed as architecture references only:

- Temporal TypeScript SDK / Temporal durable execution: strong durability and workflow semantics, but too heavy for the local M01 execution path and not required while Radlina already has durable SQLite/idempotency primitives.
- XState v5: useful state-machine/actor model and zero-dependency design, but it does not by itself provide Radlina's durable execution/security boundary.
- BullMQ: mature distributed queue, but it adds Redis as an operational dependency that M01 does not require.
- Model Context Protocol Tasks extension: directionally aligned with durable jobs, but treated as an interoperability target rather than the V2 persistence boundary until the extension is stable in the official SDK line used by Radlina.

No source code from these projects is copied into V2 M01.

## Consequences

- Capability growth is decoupled from Core growth.
- Security remains fail-closed and capability-specific.
- Durable operator execution can survive client disconnects; restart recovery does not guess at unsafe external outcomes.
- Later V2 milestones can add persistent component lifecycle controls, provider packages, richer verification contracts, and bounded parallel/DAG execution without replacing the M01 persistence model.
- V3 self-healing can reuse the clean local reliability work as reviewed internal provenance, but V2 does not merge that branch into the Golden-derived line.
