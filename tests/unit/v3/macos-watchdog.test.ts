import { describe, expect, it } from "vitest";

import {
  buildWatchdogState,
  type WatchdogChecks,
} from "../../../scripts/operations/v3-macos-watchdog.js";

const healthy = (): WatchdogChecks => ({
  macOSAgent: { ok: true, detail: "agent:running" },
  signedHeartbeat: { ok: true, detail: "2026-10-11T01:00:00.000Z" },
  githubRunner: { ok: true, detail: "runner:running" },
  gitCommit: { ok: true, detail: "a".repeat(40) },
  lastTest: { ok: true, detail: "2026-10-11T01:00:00.000Z@aaaaaaaaaaaa" },
  tailscale: { ok: true, detail: "rezanory.github:connected" },
});

describe("macOS operational watchdog state", () => {
  it("reports healthy without granting production acceptance", () => {
    expect(
      buildWatchdogState(undefined, healthy(), new Date("2026-10-11T01:00:00Z")),
    ).toMatchObject({
      status: "HEALTHY",
      consecutiveFailures: 0,
      connectionStatus: "CONNECTED",
      officialCompletionPercent: 85.71,
      productionAcceptance: "NOT_GRANTED",
    });
  });

  it("becomes BLOCKED only after three consecutive failed checks and then recovers", () => {
    const failed = healthy();
    failed.macOSAgent = { ok: false, detail: "not running" };
    const first = buildWatchdogState(undefined, failed);
    const second = buildWatchdogState(first, failed);
    const third = buildWatchdogState(second, failed);
    expect(first.status).toBe("DEGRADED");
    expect(second.status).toBe("DEGRADED");
    expect(third).toMatchObject({ status: "BLOCKED", consecutiveFailures: 3 });
    expect(buildWatchdogState(third, healthy())).toMatchObject({
      status: "HEALTHY",
      consecutiveFailures: 0,
    });
  });
});
