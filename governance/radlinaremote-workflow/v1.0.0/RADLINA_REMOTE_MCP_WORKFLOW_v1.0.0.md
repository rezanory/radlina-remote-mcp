# Radlina Remote MCP Workflow
## CSEW-Governed + Evidence-Driven + Multi-Device-Ready Edition

**Document ID:** RADLINA-REMOTE-MCP-WORKFLOW
**Short name:** RRMW
**Workflow version:** 1.0.0
**Status:** PROTECTED_PROJECT_WORKFLOW
**Date:** 2026-10-07
**Repository:** `rezanory/radlina-remote-mcp`

## 0. Purpose

This document is the project-specific execution and governance workflow for Radlina Remote MCP.
It exists so that any zero-context human, ChatGPT session, AI worker, CI runner, or future device can
reconstruct how this repository MUST be developed, validated, released, and operated without relying on
chat memory.

This workflow does not replace the Canonical Software Engineering Workflow (CSEW). It adopts an exact
CSEW version and adds Radlina-specific rules.

## 1. Authority hierarchy

When rules conflict, authority is resolved in this order:

1. User's explicit current directive.
2. Safety/security constraints and protected operational controls.
3. Adopted CSEW exact version/hash.
4. This RRMW exact version/hash.
5. Frozen project contracts / ADRs / schemas.
6. Authoritative capability DAG and exact evidence.
7. Repository documentation.
8. Chat memory, agent memory, historical notes, and informal assumptions.

Chat memory is NEVER canonical project state.

## 2. Adopted CSEW baseline

This project explicitly adopts:

- CSEW version: `3.1.5`
- Canonical path: `rezanory/chat_assistant/governance/csew/v3.1.5/`
- Workflow SHA-256:
  `fe48231026cdcd8ed75def9d2c6fa17fd20eb772f8db8faad663d2a05b7d6818`
- Manifest SHA-256:
  `341d9a3080400b5145cd57915954adf547e536d196215b9598be99f3e0662015`

A newer CSEW version MUST NOT silently replace this baseline.
Adoption of a newer CSEW requires an explicit protected change with evidence.

## 3. Frozen production baseline at RRMW 1.0.0 creation

The proven V2 baseline is:

- Product version: `2.0.0-alpha.2`
- Generation: `v2-smart-operator`
- Branch: `generation/v2-smart-operator`
- Commit: `df9d005c49e8f4ceb25105a81e33236f44543e54`
- Tree: `10bd0e7a0022987550b96795cdd1e9013e9975e2`
- Active release manifest:
  `6dde7ef6d4d56ff81f630432a4b70171beaf780bdffe5525fa85973fe255aa1e`
- Final native ChatGPT operator acceptance: PASS
- Final verdict: `REAL_PRODUCTION_READY`

V2 is a rollback and compatibility baseline for V3. V3 development MUST NOT rewrite this historical evidence.

## 4. Product and workflow versioning are independent

Two separate version streams exist.

### 4.1 Product version
SemVer-style product releases:

- `2.0.0-alpha.2`
- `3.0.0-alpha.1`
- `3.0.0-beta.1`
- `3.0.0`

Git tag namespace:

`product/v<version>`

Example:

`product/v2.0.0-alpha.2`

### 4.2 Workflow version
RRMW changes independently:

- `1.0.0`
- `1.1.0`
- `2.0.0`

Git tag namespace:

`workflow/v<version>`

Changing product code does not automatically change RRMW.
Changing RRMW does not automatically change product version.

## 5. Canonical local layout

The canonical Windows project root is:

`C:\radlina-remote-mcp`

Tracked repository/runtime files remain directly under that root because the production Windows service
currently resolves:

`C:\radlina-remote-mcp\service\RadlinaRemoteMCP.exe`

Non-source local state MUST live under:

`C:\radlina-remote-mcp\.local\`

Canonical local layout:

```text
C:\radlina-remote-mcp\
├─ src\
├─ tests\
├─ service\
├─ config\
├─ governance\
├─ docs\
├─ .state\
├─ .runtime\
└─ .local\
   ├─ worktrees\
   │  ├─ primary\
   │  ├─ integration\
   │  └─ governance\
   ├─ evidence\
   ├─ archives\
   ├─ baselines\
   ├─ candidates\
   ├─ releases\
   ├─ validation\
   └─ legacy\
```

`.local/` MUST NOT be committed.

## 6. Repository / branch model

The dedicated GitHub repository is:

`rezanory/radlina-remote-mcp`

Protected conceptual branch roles:

- `production/*` — accepted production lineage.
- `generation/v2-smart-operator` — frozen V2 Smart Operator release lineage.
- `generation/v3-multidevice-agent-os` — V3 product development line.
- `governance/*` — workflow, policy, and governance changes.
- `fix/*` — bounded fixes with explicit affected scope.

Rules:

- No `reset --hard` on shared/canonical work.
- No `git clean -fd` on shared/canonical work.
- No force push.
- Exact SHA must be recorded before protected validation.
- A production candidate becomes immutable before independent validation.
- Worktree and branch are execution containers, not project truth.

## 7. Component-first development

The unit of progress is Component/Capability, not chat, branch, phase, or commit.

Every Component MUST define:

- owner
- contract
- capabilities
- inputs / outputs
- persistent state ownership
- dependencies
- risk
- platform applicability
- acceptance requirements
- exact source candidate
- evidence

Phase numbers are roadmap metadata only.
The authoritative dependency source is the DAG.

## 8. Platform architecture rule

Technology and OS-specific concerns MUST be isolated behind stable ports/contracts.

Required direction for V3:

```text
Core / Workflow / Policy
        |
        v
Platform Contracts
   |            |
Windows      macOS
Adapter      Adapter
```

Core business/execution semantics MUST NOT directly depend on:

- Windows Service APIs
- launchd
- DPAPI
- Keychain
- Windows path semantics
- POSIX path semantics
- PowerShell/cmd
- zsh/sh
- Tailscale implementation details
- a single AI provider

## 9. V3 architecture governance

V3 is defined as:

**Secure Multi-Device + Multi-Worker + Plugin-Based Smart Operator Platform**

The product architecture SHOULD contain these bounded capabilities:

- Control Plane
- Device Registry
- Device Identity
- Device Router
- Device Agent Protocol
- Windows Agent
- macOS Agent
- Canonical Workflow Adapter
- Capability Runtime
- Artifact Bus
- Workspace / Worktree Runtime
- Plugin Runtime
- Agent Provider Runtime
- Fleet Upgrade / Rollback
- Distributed Audit

Workflow/DAG/Scheduler/State/Persistence/Recovery/Observability MUST NOT be re-invented inside Smart Operator
if an accepted canonical workflow contract already owns that responsibility.

Smart Operator is an entry adapter into the canonical workflow runtime, not a second workflow engine.

## 10. Device model

Device MUST become a first-class identity.

Minimum device descriptor:

- deviceId
- hostname
- platform
- architecture
- agentVersion
- status
- lastSeen
- capabilities
- tags
- trustState
- health

Routing MUST be evidence-based and policy-bounded.

A future V3 step may target:

- explicit `deviceId`
- capability selector
- platform selector
- approved tag selector

Silent routing to a different device is forbidden when exact-device identity is part of acceptance.

## 11. Workflow execution model

V2 sequential operator contracts remain compatibility inputs.

V3 MAY translate them to an internal canonical workflow DAG.

The DAG is the only dependency authority.

A step contract SHOULD support:

- id
- target / device selector
- capability
- input
- dependsOn
- maxAttempts
- timeout
- execution policy
- expected output contract

Parallelism is permitted only when dependencies, ownership, shared resources, policy, and validation capacity permit it.

## 12. Worktree / lane rules

Every mutating worker on shared repository scope SHOULD use a dedicated worktree.

Each lane MUST have:

- one owner
- bounded component scope
- source baseline SHA
- branch
- worktree path
- admission record
- output/evidence contract

A lane MUST NOT modify another lane's owned component without explicit ownership transfer or protected shared-core change.

Integration worktrees are not authoring worktrees.

## 13. Tool preference

For operations on the Windows production machine:

1. Radlina Remote Full MCP
2. Remote Desktop Commander only as fallback or for self-maintenance scenarios Radlina cannot safely execute
3. GitHub connector for remote repository evidence/actions
4. Other tools only when required by the task

Codex MUST NOT be used for this repository unless the user explicitly reverses this project rule.

## 14. Security invariants

All externally reachable MCP execution MUST be authenticated.

Required invariants include:

- fail-closed authorization
- bounded scopes
- token expiry
- refresh rotation
- replay protection
- persistent trusted-owner rules only where explicitly configured
- idempotency on protected mutating operations
- path boundary enforcement
- symlink escape protection
- command/process policy
- timeout/cancellation
- auditability
- kill switch
- emergency read-only mode

V3 adds Device Identity and Agent Identity without weakening User Identity.

## 15. Audit invariants

Protected execution MUST emit evidence sufficient to answer:

- who requested it?
- which exact device executed it?
- which capability?
- which policy decision?
- which exact input identity/hash?
- which output identity/hash?
- which job/step?
- when?
- what terminal state?
- what receipt/audit hash?

Distributed audit MUST preserve local device evidence and global workflow correlation.

## 16. Real Operational Acceptance

Automated tests are mandatory but never sufficient for executable production claims.

For executable scope, PASS requires a real chain:

`Input → Runtime → Execution → Output → Acceptance`

For UI scope, real interactive frontend validation is an additional independent gate.

For native ChatGPT MCP acceptance, PASS requires ChatGPT itself to invoke the native tool.
Shell, direct HTTP, browser automation, or another tool calling the same backend does not satisfy that claim.

## 17. Native Smart Operator acceptance

When Smart Operator is in scope, final acceptance requires at minimum:

1. Fresh/valid ChatGPT plugin tool catalog.
2. Native `operator_submit`.
3. Real returned jobId.
4. Native `operator_status` until terminal.
5. Final state `completed`.
6. Server-side audit corroboration for the same job.
7. No fallback masquerading as native acceptance.

If ChatGPT exposes a stale tool catalog:

1. Confirm server capability/tool registration.
2. Reconnect account if needed.
3. Use ChatGPT Developer Plugin `Refresh tools`.
4. Create a fresh chat with `Try in chat`.
5. Re-run only the missing native acceptance gate.
6. Do not repeat already-accepted server/release gates without evidence they are affected.

## 18. Testing model

Default is collect-all, not fail-fast, unless continuing is unsafe or technically impossible.

Testing is impact-based:

- changed component
- direct dependencies
- direct consumers
- shared backbone affected by the change
- platform adapters affected
- security surfaces affected

A previous unaffected PASS MAY be reused by exact evidence identity.

## 19. Independent validation

The authoring lane MUST NOT self-certify protected readiness.

Validation MUST consume an immutable exact source candidate.

Validator may report findings but MUST NOT silently patch the candidate being validated.

Fixes create a new candidate and invalidate only affected evidence.

## 20. Release model

Release readiness and activation are separate.

States:

`AUTHORED → VALIDATED → ACCEPTED → DORMANT/READY → ACTIVE`

A component can be accepted but not activated.

Every product release MUST record:

- product version
- source commit
- tree SHA
- release manifest hash
- workflow version
- adopted CSEW version/hash
- platform(s)
- acceptance receipts
- rollback candidate

## 21. Upgrade / rollback

V2 must remain a valid rollback path until V3 compatibility closure explicitly retires it.

V3 fleet changes SHOULD use:

1. plan
2. preflight
3. canary
4. health/readiness
5. real operational acceptance
6. staged rollout
7. rollback proof

A failed canary blocks expansion but does not authorize destructive rollback outside defined scope.

## 22. Multi-device acceptance

V3 cannot claim multi-device readiness until at least two real devices are registered and independently exercised.

Minimum target:

- Windows device health PASS
- macOS device health PASS
- real process execution Windows PASS
- real process execution macOS PASS
- parallel cross-device execution PASS
- dependency join PASS
- interruption/reconnect PASS
- artifact integrity PASS
- distributed audit PASS

Synthetic-only multi-device tests do not close this gate.

## 23. Anti-blocker / anti-stall

A blocked lane is not a project-wide blocker if other admitted DAG work exists.

On stall:

1. detect
2. collect evidence
3. classify
4. recover/rebind/retry if policy permits
5. preserve idempotency
6. continue unaffected lanes
7. escalate only when exact blocker proof exists

Blind infinite retry is forbidden.

## 24. Evidence locations

Tracked, long-lived normative evidence belongs in repository paths appropriate for governance/release records.

Large local operational evidence belongs under:

`C:\radlina-remote-mcp\.local\evidence\`

Historical local archives:

`C:\radlina-remote-mcp\.local\archives\`

Release payloads:

`C:\radlina-remote-mcp\.local\releases\`

Temporary worktrees:

`C:\radlina-remote-mcp\.local\worktrees\`

No future root-level sibling directory named `C:\radlina-remote-mcp-*` SHOULD be created.

## 25. Canonical handoff

Every substantial lane handoff MUST include:

- project/repository
- component/lane
- exact branch
- exact commit/tree
- worktree path
- completed work
- validation evidence
- unresolved blockers
- next admissible action
- forbidden/repeated work
- workflow version
- CSEW adoption identity

A new chat MUST be able to continue from this without relying on prior conversation.

## 26. Protected change protocol

The following require explicit scoped change evidence:

- security model
- auth/OAuth
- policy semantics
- audit semantics
- device identity
- workflow state machine
- DAG semantics
- persistent schema
- public MCP contract
- release/rollback behavior
- RRMW normative rules
- adopted CSEW version

## 27. RRMW completion rule

No milestone is `100% COMPLETE` while any known in-scope production requirement, required test,
required real operational validation, high/critical defect, or protected evidence gap remains unresolved.

`PRODUCTION_READY` is not the same as `PRODUCTION_ACTIVE`.

## 28. Zero-context bootstrap

A zero-context receiver SHOULD perform, in order:

1. Read `governance/radlinaremote-workflow/LATEST.json`.
2. Verify referenced workflow manifest and hashes.
3. Read `governance/radlinaremote-workflow/README.md`.
4. Read exact RRMW workflow.
5. Read adoption record.
6. Read `VERSIONING.md`.
7. Inspect repository exact HEAD/status.
8. Inspect active product release manifest.
9. Resume only from exact evidence; never infer completion from chat history.

---
**END RRMW 1.0.0**
