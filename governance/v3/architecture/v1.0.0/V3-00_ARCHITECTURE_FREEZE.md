# Radlina Remote MCP V3-00 Architecture Freeze
## CSEW Adoption + Existing Workflow Reconciliation + V3 Architecture Freeze

**Architecture contract version:** 1.0.0
**Project:** rezanory/radlina-remote-mcp
**Product line:** V3 — generation/v3-multidevice-agent-os
**RRMW:** 1.0.0
**Adopted CSEW:** 3.1.5
**Status:** FROZEN

## 1. Evidence boundary

This freeze was produced from exact, read-only inventories before any V3 executable implementation.

Radlina Remote MCP V3 starting source:
- commit: 98d539158c34d4720452d3f726595b31ebfd234e
- tree: 24dd435c5b1d5239101ebaf8ed7810366cf5f70d
- local branch/worktree was clean and exactly synchronized with github/generation/v3-multidevice-agent-os.

Protected V2 production baseline:
- product: 2.0.0-alpha.2
- commit: df9d005c49e8f4ceb25105a81e33236f44543e54
- tree: 10bd0e7a0022987550b96795cdd1e9013e9975e2
- active release manifest: 6dde7ef6d4d56ff81f630432a4b70171beaf780bdffe5525fa85973fe255aa1e
- verdict: REAL_PRODUCTION_READY
- native ChatGPT acceptance remains historical PASS and is not repeated by V3-00.

Workflow-reference snapshot:
- repository: rezanory/radlina-intelligence
- commit: 3ab4874892b5e9b01578918faa63607ebdb3dec6
- tree: 09a6f120138b87a650bf6107c6e80193015d9525
- local/remote branch identity was exact at inventory time.
- unrelated untracked files in that repository were not modified.

## 2. Reconciliation verdict

The generic radlina-intelligence workflow taxonomy is useful, but most requested files under workflows/dag, workflows/engine, workflows/scheduler, workflows/state, workflows/persistence, workflows/recovery and workflows/triggers are minimal stubs. They are therefore contract/taxonomy references, not production implementations.

The richer provider layer contributes useful semantics for:
- durable-provider ports,
- execution identity and idempotency,
- timeout/retry metadata,
- scheduling timestamps,
- status normalization,
- cancellation/resume,
- correlation/tracing,
- optional Temporal-style bridges,
- operational metrics.

Those semantics are adapted, not copied blindly. The native SQLite workflow provider explicitly identifies itself as test/replaceability-only and cannot satisfy production durable-orchestration evidence.

The exact item-by-item disposition is frozen in V3_REUSE_RECONCILIATION.json.

## 3. Frozen architecture

V3 is:

CSEW-governed
→ Canonical Workflow Runtime
→ Radlina V2 security/execution core adapted into a multi-device platform backbone.

The only valid orchestration path is:

ChatGPT
→ operator_submit
→ Smart Operator Adapter
→ Canonical Workflow Runtime
→ Authoritative DAG
→ Scheduler
→ ExecutionDispatchPort
→ Device Router
→ Windows/macOS Device Agent
→ capability execution
→ local receipt + output
→ canonical workflow state/output acceptance.

Smart Operator is not a workflow engine.

## 4. Single-authority rules

The Canonical Workflow Runtime exclusively owns:
- DAG validation and dependency semantics,
- workflow/node state machines,
- scheduling,
- workflow persistence,
- retry/recovery/resume rules,
- workflow observability,
- triggers.

No MCP handler, operator adapter, device agent, plugin, provider or artifact service may create a parallel state machine or scheduler.

The authoritative dependency graph is V3_COMPONENT_CAPABILITY_DAG.json.

## 5. V2 compatibility

V2 stays at 100% and remains the rollback baseline.

On the V3 path, the current sequential OperatorManager is replaced as an orchestration engine, but the public operator_* experience remains compatible. Legacy ordered steps are translated into a DAG chain. The returned public jobId is the canonical workflow execution id.

Existing V2 OAuth/user identity, fail-closed policy semantics, kill switch, emergency read-only controls, audit tamper evidence, idempotency safeguards and release verification are preserved or extended behind stable ports.

## 6. Device and platform boundary

Device is first-class. A DeviceDescriptor carries deviceId, hostname, platform, architecture, agentVersion, status, lastSeen, capabilities, tags, trustState and health.

An execution attempt always records the resolved device. Exact device selectors cannot silently fail over.

Core workflow code must not directly import DPAPI, Keychain, WinSW, launchd, PowerShell/cmd, zsh/sh, Windows/POSIX path semantics or Tailscale implementation details.

DPAPI becomes the Windows SecretProtectorPort implementation. macOS receives a Keychain-backed implementation.

## 7. Persistence and recovery

Canonical workflow persistence has one writer: workflow.persistence.

V2 operator_jobs/operator_steps remain historical V2 implementation details and are not authoritative V3 workflow state.

Recovery first reconciles durable state with device receipts. Automatic retry of a non-idempotent attempt with an unknown/interrupted outcome is forbidden.

## 8. Distributed audit and artifacts

Every distributed execution correlates a global workflow/node/attempt identity with the exact resolved device and its local audit receipt hash.

Artifacts are content-addressed and verified by SHA-256 and size at the consumer boundary. Artifact transfer never owns workflow dependency semantics.

## 9. Ownership boundaries

Workflow Core owns DAG/state/scheduler/persistence/recovery/observability/triggers.

Platform Backbone owns platform ports, device registry infrastructure, capability runtime, routing and fleet lifecycle.

Device Plane owns device identity proof, the agent protocol, OS adapters and local execution receipts.

Operator Adapter owns validation/translation/status projection only.

Artifact Plane owns artifact identity/metadata/transfer/integrity only.

Plugin and Agent Provider runtimes own provider lifecycle and bounded invocation, never policy bypass or canonical scheduling.

## 10. Initial admitted implementation

After this freeze is committed, exactly two independent first lanes are admitted:

1. W01 — workflow.contracts
2. P01 — platform.contracts

They may progress in parallel because their dependencies are only this architecture freeze. No other new V3 component is admitted until its DAG prerequisites are satisfied.

W01 acceptance must cover schema/type validity, cycle/missing dependency rejection, selector contracts and legacy V2 operator-plan translation semantics.

P01 acceptance must prove platform-neutral contracts with no OS-specific imports and conformance fixtures for both Windows and macOS adapters.

## 11. Acceptance constraints

Executable production scope is never closed by unit/integration tests alone. Final claims require the real chain:

Input → Runtime → Execution → Output → Acceptance.

Multi-device readiness additionally requires two real enrolled devices and real Windows/macOS execution, cross-device parallelism, dependency join, reconnect/recovery, artifact integrity and distributed audit.

Native ChatGPT acceptance must invoke native plugin tools; shell/HTTP/browser substitutes do not count.

## 12. Freeze change protocol

Changes to device identity, workflow state machine, DAG semantics, persistence ownership, public MCP contracts, policy/audit semantics, or release behavior require a protected architecture revision with affected-scope evidence.

RRMW 1.0.0 is not automatically version-bumped by product architecture work. Product, RRMW and architecture-contract versions remain distinct.

---
END V3-00 ARCHITECTURE FREEZE 1.0.0
