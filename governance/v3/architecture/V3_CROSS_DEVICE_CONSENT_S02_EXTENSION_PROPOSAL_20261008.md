# V3 cross-device permission — protected S02 extension proposal

- **Change request:** V3-SEC-CONSENT-01
- **Status:** IMPLEMENTATION CANDIDATE / PROTECTED ARCHITECTURE REVIEW PENDING
- **Canonical architecture freeze:** 1.0.0 unchanged
- **Component ownership:** S02 Security Policy, P03 identity/registry, P06 router, C01 control plane, S03 distributed audit; I01 composes them
- **Official progress:** 24/28 accepted (85.71%). P08 remains implemented but not real-MacBook accepted.

## Requested invariant

A task from `windows-main` to `macbook-main`, or the reverse, must not communicate with or execute on the other device until the **recipient device owner** explicitly approves the **specific action**. Approval in one direction grants **no** reverse access. Enrollment and tailnet membership are **not** consent.

Permission requests must show: source and target device, authenticated requester, exact capability, safe human-readable operation and resource summary, input SHA-256 fingerprint, purpose, risk level, requested window and effect of "allow". **Default deny**; offline recipient = deny (or request queued without execution). No silent consent from SSH, UI automation, ChatGPT, or an agent.

The proposed local UI offers: **Deny**, **Once**, **15 minutes**, **1 hour**, **8 hours**, **24 hours**, **Custom up to 30 days**, **Permanent until revoked**. All allow decisions are device/subject/capability/resource/input scoped; **permanent never means unrestricted access**. High-risk permanent grants should require a second locally authenticated confirmation. A recipient can revoke an active grant; expiry or revocation blocks subsequent attempts. In-flight execution requires stop/cancel and revalidation hooks before final production acceptance.

## Security boundaries

1. **Identity plane**: P03 trusted device registry must pin each device's distinct Ed25519 public key, verify enrolled identity and authenticate the local approval UI. Merely writing `deviceId: macbook-main` or `trusted: true` is not proof of a real MacBook.
2. **Approval plane**: Target signs the complete request hash, direction, decision, lifetime and nonce using a target-held private key protected by macOS Keychain/Windows DPAPI. No private signing key goes into MCP responses or SQLite. A remote caller cannot impersonate the approving side.
3. **Application plane**: An immutable verified originating-device binding accompanies each workflow. A consent check is required before every remote dispatch. An exact-device selector may not reroute, and a new input hash or capability needs a new approval. Once-only grants are atomically consumed; retry cannot reuse them. Remote target must also revalidate consent before executing the capability, and revocation must reach ongoing long-running sessions.
4. **Network plane**: Tailscale Grants/ACLs must deny direct Mac↔Windows data ports by default. The only pre-consent exception can be a tightly limited **authenticated approval/rendezvous channel**, ideally through a broker so peers have no general network connectivity. For truly direct peer traffic, apply an additional least-privilege, short-lived network grant and remove it on expiry/revoke; JIT provisioning must use policy revision compare-and-swap, tests, recovery after restart, continuous reconciliation and audited rollback. A one-hour Radlina permission does **not** itself close an open Tailscale TCP port.
5. **Audit plane**: Store request/target-signed decision/consumption/expiry/revocation/denial. Hash chaining is implemented in the candidate, but its head must be externally anchored/signed by S03. A hash chain in a mutable DB alone is not tamper-proof.
6. **Governance**: The canonical workflow runtime remains the sole workflow engine. S02 owns consent policy, P03 owns enrolled identities, P06 owns routing, S03 owns final audit. This does not create a parallel scheduler or change the V2 release.

## Candidate code (not activated in production)

- `src/v3/security/consent-contracts.ts`: strict, exact-scope request and target-signed approval contracts
- `src/v3/security/device-consent.ts`: durable SQLite consent authority, Ed25519 verification, TTL, revocation, atomic once-only usage and event chain
- `src/v3/security/consent-dispatch.ts`: V3 dispatch port adapter with trusted origin, exact target binding and no silent fallback
- `tests/unit/v3/device-consent.test.ts`: negative security cases and operation-level policy checks

The candidate is **NOT** an active cross-device network firewall. Until the actual MacBook is enrolled, the Tailscale policy is reviewed and the C01/P06/P08/I01 transport is wired and operationally tested, it must not claim communication has been blocked at all network layers. No production tailnet policies or V2 services were modified.

## Operational acceptance gates still required

- Both real devices enrolled; separate target held signing keys and local approval UI; no server-side auto approval
- Authenticated approval request shown only on recipient, approve/reject audited on that device
- Negative tests: no approval, wrong direction, wrong device/subject, wrong action/input/resource, forged signature, expired permission, revoked permission, source spoof, key rotation, replayed once token, simultaneous requests
- Tailscale deny-before-permission in both directions (proof via real TCP attempts), bootstrap approval channel only
- Real network grant/allow limited operation, expiry and revoke close access (including established sessions), restart recovery and policy revision race rejection
- Real Windows→Mac and Mac→Windows execution, correlated signed audit receipts and independent acceptance
- V2 2.0.0-alpha.2 production manifest/health unchanged and full affected-scope regression PASS

## External references

- Tailscale Grants: https://tailscale.com/docs/features/access-control/grants
- Tailscale JIT access: https://tailscale.com/docs/features/access-control/just-in-time-access
- Tailscale policy-file editing, validation and admin authorization: https://tailscale.com/docs/features/tailnet-policy-file/manage-tailnet-policies

**END V3-SEC-CONSENT-01 PROPOSAL — NOT PRODUCTION ACCEPTANCE**
