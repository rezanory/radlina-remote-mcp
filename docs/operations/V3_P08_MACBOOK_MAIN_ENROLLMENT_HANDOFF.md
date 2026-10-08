# P08 — Real MacBook enrollment readiness handoff

- **Repository:** `rezanory/radlina-remote-mcp` (private)
- **Canonical branch:** `generation/v3-multidevice-agent-os`
- **Real device:** `macbook-main` (owner's physical macOS computer)
- **Windows reference:** `LAPTOP-13QINEIF` / `laptop-13qineif.taile17c9e.ts.net`
- **Tailnet:** `rezanory.github`
- **MagicDNS suffix:** `taile17c9e.ts.net`

This document is self-contained for use on the owner's **separate MacBook and separate ChatGPT account**. The MacBook does not automatically inherit this conversation's context or Windows tooling.

## What is already done

- P08 macOS adapter code is in the canonical V3 repository.
- GitHub-hosted `macos-latest` successfully ran Keychain, filesystem, process, search and MacOSDeviceAgent component checks (Actions run `37704820070`).
- A self-hosted macOS readiness workflow and fail-closed identity checks are available.
- Official V3 production-accepted implementation remains **24/28 (85.71%)**. A hosted macOS runner is **not** the owner's MacBook.

## Required actions on the actual MacBook

1. Install and sign in to Tailscale. The Mac must join the **same** `rezanory.github` tailnet, not a new/independent tailnet. Confirm `tailscale status --json` shows backend `Running`, self OS `macOS`, and MagicDNS `taile17c9e.ts.net`.
2. Record the actual Mac's Tailscale `Self.ID`, `Self.HostName` and `Self.DNSName`. This is a **candidate identity only**. Do not auto-approve it merely because it came from a local environment variable.
3. Independently verify the Mac is the owner's machine and the **same node ID** appears in Windows' Tailscale peer inventory. The approved ID must be pinned by the repository owner as the GitHub Actions secret `RADLINA_APPROVED_MAC_TAILSCALE_NODE_ID`. Do not send any auth key, GitHub runner registration token or secret to ChatGPT.
4. Install Node.js **v24.20.0**, Git, ripgrep (`rg`) and the Tailscale CLI. The `security` CLI comes from macOS. Check `node --version`, `git --version`, `rg --version` and `tailscale status`.
5. Create an authorized GitHub **self-hosted macOS runner** for the private repository using GitHub's **Settings → Actions → Runners → New self-hosted runner** instructions. Apply the custom label `radlina-macbook`. Do not reuse the Windows runner. Keep any GitHub registration token local and confidential.
6. From GitHub Actions select **V3 P08 Real MacBook Readiness (NOT Production Acceptance)** and dispatch on branch `generation/v3-multidevice-agent-os`. The workflow runs only on the macOS self-hosted runner, requires the approved node ID secret, verifies a Tailscale ping to Windows, then runs targeted tests and real Mac component checks.
7. Review the `v3-p08-macbook-readiness-not-production-acceptance` artifact and the connected Radlina V3 device registry's **trusted** identity claim. A local readiness PASS, a GitHub green check, or a logical `macbook-main` string alone **must not** grant production acceptance.

## Evidence and remaining gate

The read-only local readiness output explicitly distinguishes:
- `readiness=PASS`: physical macOS host passed owner-pinned Tailscale/network checks and local component runtime checks
- `productionAcceptance=PENDING_TRUSTED_DEVICE_REGISTRY_AND_LIVE_ROUTE_ACCEPTANCE`: the Mac is **not yet** proven trusted and routable by the canonical V3 control plane

Final P08 acceptance requires a separately reviewable real chain:

`Approved owner Mac identity → trusted P03 registry record → P06 exact-device route → P08 MacOSDeviceAgent execution → correlated audited receipt → independent acceptance`

Only after that chain is witnessed may P08 be added to the **official accepted** count and F01/I01/AC01 be unblocked. No proof may be fabricated from hosted CI, a test fixture, or manually edited JSON.

## Workflow source

- `scripts/enrollment/macbook-readiness-policy.ts` — pure fail-closed checks
- `scripts/acceptance/v3-p08-real-macbook.ts` — Mac-local readiness, Windows reachability and component smoke test
- `scripts/enrollment/v3-p08-real-macbook-acceptance.sh` — wrapper for the Mac runner (readiness only)
- `.github/workflows/v3-p08-real-macbook-acceptance.yml` — restricted macOS self-hosted job
- `tests/unit/v3/macbook-readiness-policy.test.ts` — negative cases and approved-identity case

**Do not** enable production V3 or change V2 release manifest to execute this readiness workflow. V2 `2.0.0-alpha.2` must remain healthy.
