# V3 P08 real MacBook acceptance workflow — inactive draft

The YAML draft is intentionally inert and versioned under `docs/operations/`, outside `.github/workflows/`. Its automatic `push` trigger has been removed, and its macOS job has `if: false`, so publishing it cannot execute a MacBook-side action. An independent recovery backup retains the original version.

The source draft used an automatic `push` trigger for a self-hosted macOS runner and an outbound Tailscale probe. It has **not** been activated as a GitHub Actions workflow because the requested per-action cross-device consent gate has not been demonstrated in that execution path.

Activation requirements:
1. MacBook-side consent must be explicit, scoped to the specific action/device, revocable, and either time-bounded or permanently granted by the receiving side.
2. Before any MacBook-side probe or execution, verify the consent grant through the authoritative V3 policy path; a GitHub event, runner label, and network connectivity are not consent.
3. Fail closed for missing, expired, or revoked consent, with durable audit evidence.
4. Require an independent real-MacBook operational acceptance before promoting this draft to `.github/workflows/`.

The original draft was backed up under the local synchronization evidence directory before being moved. No real MacBook test has been claimed as passed by this synchronization step.
