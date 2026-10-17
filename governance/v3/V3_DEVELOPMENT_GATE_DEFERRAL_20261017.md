# Radlina V3 — Development-only gate deferral (2026-10-17)

**Scope:** `rezanory/radlina-remote-mcp`, isolated V3 only. Owner directed that review/sign-off bottlenecks must not freeze implementation and non-production testing. This is a development workflow, **not** a production exemption, real cross-host deployment or gate acceptance.

## Effective policy

- Development/public-policy preparation can proceed before a separate final-review signature or public key is available.
- Real P03 Windows/Mac identities, exact owner OAuth identity, real owner Ed25519 signature, and genuine separate Mac S03 public witness key still apply. Never create substitute credentials or claim fabricated consent.
- `--prepare-development` with the existing `radlina.v3.final-four-owner-provision/v1` input **omits** `independentReviewerPublicKeyFile`. It writes to `E:\\radlina-v3-oauth-standalone\\final4\\development-only-owner-policies` and emits the distinct schema `radlina.v3.final-four-development-binding/v1`, with `developmentOnly=true`, `productionActivationPermitted=false`, `gateAcceptancePermitted=false`.
- `--prepare` is unchanged as the actual production path: it requires a valid genuine reviewer public key, owner DPAPI protected signing, true P03 identities and independent S03 key.
- Production `v3-final4-gateway-stage.ps1` rejects development-only schema or a missing reviewer key *before* writing the candidate or changing any service. The physical V3 composition also accepts only `radlina.v3.final-four-production-binding/v1`.
- This development workflow does not change any V2 service, registered ChatGPT OAuth permissions, Tailscale admission, external MCP tool safety controls, Keychain/DPAPI access policies, final physical S02E recipient-local consent or independently signed S03 acknowledgment. It does not activate any executable V3 port.

## How to use

Run on the authorized, interactive Windows owner environment after a real native ChatGPT owner identity and actual Mac S03 witness public-key file have been provisioned:

```powershell
node node_modules/tsx/dist/cli.mjs scripts/operations/v3-final4-owner-policies.ts --prepare-development E:\path\to\owner-provision-input.json
```

The input JSON uses the documented `radlina.v3.final-four-owner-provision/v1` schema and the real public key file paths, **excluding** `independentReviewerPublicKeyFile`. No bearer/HMAC material belongs in this input or in source control. Do not run this command under SYSTEM; the owner signer expects the existing logged-in owner identity.

The output is explicitly **not installable**, even with its matching SHA-256. For live deployment, use the normal reviewed `--prepare` and owner-pinned `Stage → Apply` workflow, real S03 writer credentials in protected storage and genuine device-local consent.

## Acceptance and expiration

Development deferral ends automatically at the physical deployment/acceptance boundary. Do not increase the official accepted-gate count based on these files, source tests, or deployment preflights. Final governance is to be reconciled to ChatGPT-as-reviewer before AC01, without inventing a cryptographic ChatGPT signing identity. Until resolved, final live acceptance remains fail closed.

## Validation

`tests/unit/v3/final4-development-gating.test.ts` exercises development mode, production mode, invalid downgrade, nondeployable output, gateway rejection and preserved recipient-local/S03 dependencies. TypeScript, ESLint and PowerShell syntax checks must pass; keep V3 full unit tests green.
