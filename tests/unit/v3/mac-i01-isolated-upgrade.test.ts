import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const source = readFileSync(
  resolve(process.cwd(), "scripts/operations/v3-final4-mac-upgrade.sh"),
  "utf8",
);

/** Native Mac acceptance is required separately; these are source-level guards. */
describe("Mac I01-only upgrade isolation", () => {
  it("supports explicit I01 upgrade without changing the full upgrade contract", () => {
    expect(source).toContain('"$1" == \'--upgrade-i01\'');
    expect(source).toContain('"$1" == \'--upgrade\'');
    expect(source).toContain('UPGRADE_MODE="$1"');
  });

  it("requires only I01's physical Mac entrypoints in scoped mode", () => {
    expect(source).toContain(
      "REQUIRED_SCRIPTS=(v3-mac-operator-cycle.ts v3-s03-mac-witness-daemon.ts)",
    );
    expect(source).toMatch(
      /if \[\[ "\$UPGRADE_MODE" == '--upgrade' \]\]; then\s+REQUIRED_SCRIPTS\+=\(v3-mac-fleet-cycle\.ts\)/,
    );
    expect(source).toContain('for script in "${REQUIRED_SCRIPTS[@]}"; do');
  });

  it("upgrades S03 and operator without touching Fleet in I01-only mode", () => {
    expect(source).toContain(
      "LABELS='com.radlina.remote-mcp.v3.mac-s03-witness com.radlina.remote-mcp.v3.mac-operator'",
    );
    expect(source).toMatch(
      /if \[\[ "\$UPGRADE_MODE" == '--upgrade' \]\]; then\s+LABELS="\$LABELS com\.radlina\.remote-mcp\.v3\.mac-fleet-agent"/,
    );
    expect(source).toContain("for label in $LABELS; do");
    expect(source).toContain("V3_MAC_I01_RELEASE_UPGRADE_RECORDED");
    expect(source).toContain("fleet=untouched acceptance=deferred");
  });

  it("retains immutable manifests and fail-closed migration journal", () => {
    expect(source).toContain("shasum -a 256");
    expect(source).toContain("'native-start-returned'");
    expect(source).toContain("Unreconciled V3 Mac LaunchAgent upgrade exists");
    expect(source).toContain('[[ "$refs" == \'3\' ]]');
    expect(source).toContain("launchctl bootout");
    expect(source).toContain("launchctl bootstrap");
  });
});
