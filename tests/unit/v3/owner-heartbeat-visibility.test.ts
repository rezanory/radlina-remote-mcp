import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const operations = path.join(process.cwd(), "scripts", "operations");
const helper = readFileSync(path.join(operations, "v3-owner-hidden-task-action.ps1"), "utf8");
const install = readFileSync(path.join(operations, "v3-final4-windows-install.ps1"), "utf8");
const migrate = readFileSync(path.join(operations, "v3-final4-windows-task-migrate.ps1"), "utf8");

describe("V3 owner heartbeat never flashes a PowerShell window", () => {
  it("runs all interactive roles using GUI-subsystem WScript and hidden execution", () => {
    expect(helper).toContain("System32\\wscript.exe");
    expect(helper).toContain("shell.Run(command, 0, True)");
    expect(helper).toContain("WScript.Quit exitCode");
    expect(helper).toContain("//B //Nologo");
    expect(helper).toContain("v3-final4-windows-task-launch");
  });
  it("both install and migration use the background action without altering V2", () => {
    for (const script of [install, migrate]) {
      expect(script).toContain("v3-owner-hidden-task-action.ps1");
      expect(script).toContain("New-V3HiddenOwnerTaskAction");
      expect(script).not.toContain("New-ScheduledTaskAction -Execute 'C:\\Windows\\System32\\WindowsPowerShell");
      expect(script).toContain("'\\RadlinaV3\\'");
    }
    expect(install).toContain("New-ScheduledTaskPrincipal");
    expect(install).toContain("-LogonType Interactive");
    expect(install).toContain("-RepetitionInterval (New-TimeSpan -Minutes 1)");
    expect(migrate).toContain("Preserve exact original principal, triggers and settings");
  });
});
