# I01-only Production Activation — physical readiness runbook

Date: 2026-10-17. Repository: `rezanory/radlina-remote-mcp`.
Source branch: `feature/v3-final4-composition-20261012`.

## Engineering decision

Gate #26 I01 must be able to start on owner-signed, immutable **real production** trust material without waiting for F01 release orchestration or AC01 final-review signatures. Later gates can be developed in parallel but retain their original physical acceptance order. This is **not** the existing `--prepare-development` nondeployable fixture, and not permission to skip the live security checks. The final-four configuration remains a distinct, reviewer-pinned path.

The I01-only configuration is `radlina.v3.i01-production-binding/v1` with `i01Only:true`. It still requires the genuine Windows owner Ed25519 signer, enrolled P03 Windows+Mac public keys, current trusted Tailscale node pins, registered native ChatGPT OAuth client/owner mapping, real Mac S03 witness public key, and protected S03 writer credentials. No dummy reviewer identity is created or substituted. A matching owner-signed Mac Operator capability policy with recipient-local consent remains mandatory.

## Build and preflight

1. Release source to a **new immutable V3 release** through the existing signed build/staging process. Both Windows and Mac must have matching vetted source commitments and expected manifest SHA-256; release staging is not installation.
2. On the physical Mac, run the read-only diagnostic from a trusted staged release:

```bash
RADLINA_V3_FINAL4_MAC_RELEASE_SHA256=<pinned-real-mac-manifest-hash> \
RADLINA_V3_MAC_OPERATOR_POLICY_PATH=<owner-signed-real-mac-policy-file> \
RADLINA_V3_MAC_OPERATOR_POLICY_SHA256=<owner-pinned-sha256> \
RADLINA_V3_S03_WITNESS_POLICY_PATH=<real-mac-witness-pins-file> \
RADLINA_V3_S03_WITNESS_POLICY_SHA256=<owner-pinned-sha256> \
bash scripts/operations/v3-final4-mac-i01-readiness.sh --check-i01
```

This command does not read credential bytes, attempt a Keychain lookup or modify services. It reports exact missing prerequisites; `PREREQUISITES_PRESENT_NOT_ACCEPTED` is not a gate receipt. Before installing, a locally authorized owner must use a supported secure transfer channel to provision the already generated matching S03 bearer/HMAC into the physical Mac Keychain. Never move protected secrets using CI logs, Git commits, chat, command arguments, or a tool that explicitly denies credential access. The existing Keychain staging helper can then place private 0600 files without printing their contents.

## Actual I01-only policy

Run the existing Windows owner key and P03 public-identity provisioning entrypoint **in a genuine logged-in owner session**, with a real witness public-key file and an authorized native OAuth client ID, but no AC01 reviewer key:

```powershell
node node_modules/tsx/dist/cli.mjs scripts/operations/v3-final4-owner-policies.ts --prepare-i01 E:\owner-controlled\i01-owner-input.json
```

The expected output directory is `E:\radlina-v3-oauth-standalone\final4\i01-only-owner-policies`. The command only emits public trust policies, exact file SHA-256 pins, and a real signed Mac Operator policy. All writes are create-only; if an owner policy file already exists, stop and reconcile instead of overwriting.

The native Windows Gateway service receives the exact validated, previously staged candidate through `v3-final4-gateway-stage.ps1 -I01Only -Stage`, followed by a separate explicit `-I01Only -Apply`. Both modes must receive real `ReleaseManifestSha256`, `OwnerBindingConfigPath`, `OwnerBindingConfigSha256`, `MacOperatorPolicyPath`, `MacOperatorPolicySha256`, `S03WriterTokenFile` and `S03HmacDpapiFile`. These final two are absolute file **paths**, never inline secret values. Full final-four activation without `-I01Only` continues to require a genuine final reviewer key. No V2 service, port, profile or state may be modified.

On Mac, the installer's `--install-i01` mode creates ONLY operator and independent S03 witness LaunchAgents (Fleet remains untouched), after full-release artifact verification. The separate existing Cloudflare tunnel installer must be provisioned through its genuine private ingress credentials and verified online.

## Live acceptance prerequisites

- `macbook-main` and `windows-main`: fresh trusted physical P03 heartbeats, correct real keys and Tailnet node hashes.
- Real V3 OAuth connector: `device:execute` authenticated to pinned owner account; `fleet:control` unavailable in I01-only mode.
- Real target-local recipient decision, bound to exact workflow/subject/source/target/capability/input SHA-256; no permanent bypass or synthetic consent.
- Signed request delivered to the physical Mac Operator, original Ed25519 recipient receipt returned and input/output readback validated.
- Independent Mac S03 signed append/ACK verified and durably persisted across the actual network ingress. A missing or uncertain ACK **does not permit automatic re-execution**.
- Only then may the gate #26 physical acceptance evidence be assessed under its approved governance. Running unit tests, native release preflight, OAuth tool discovery or staging a service **cannot** mark #26 accepted.
- F01 and AC01 stay **not installed / not accepted** until their own real operational tests.

## Current checkpoint at authoring

At the 2026-10-17 implementation checkpoint: hosted [GitHub CI #38990477220](https://github.com/rezanory/radlina-remote-mcp/actions/runs/38990477220) passed 50/50 source tests, typecheck and lint. Mac and Windows registered heartbeats were online; Windows was degraded. The independent Mac S03 Cloudflare tunnel was inactive with 0 connections. New source has not been confirmed installed on the actual Mac or Windows, and no verified cross-device I01 execution/S03 ACK is yet available. Official acceptance remains 25/28 = 89.29%.
