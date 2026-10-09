# V3 P08 real MacBook acceptance workflow — inactive draft

The executable YAML draft is deliberately **not committed or activated**. Its local copy remains under `docs/operations/`, outside `.github/workflows/`, with a separate recovery backup. This documentation can be published without triggering remote execution.

The source draft used an automatic `push` trigger for a self-hosted macOS runner and an outbound Tailscale probe. It has **not** been activated as a GitHub Actions workflow because the requested per-action cross-device consent gate has not been demonstrated in that execution path.

Activation requirements:
1. MacBook-side consent must be explicit, scoped to the specific action/device, revocable, and either time-bounded or permanently granted by the receiving side.
2. Before any MacBook-side probe or execution, verify the consent grant through the authoritative V3 policy path; a GitHub event, runner label, and network connectivity are not consent.
3. Fail closed for missing, expired, or revoked consent, with durable audit evidence.
4. Require an independent real-MacBook operational acceptance before promoting this draft to `.github/workflows/`.

The original draft was backed up under the local synchronization evidence directory before being moved. No real MacBook test has been claimed as passed by this synchronization step.
