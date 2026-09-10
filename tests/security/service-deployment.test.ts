import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

async function source(relativePath: string): Promise<string> {
  return await readFile(path.join(projectRoot, relativePath), "utf8");
}

describe("Windows service deployment boundary", () => {
  it("uses LocalSystem without a password prompt and applies ACL hardening", async () => {
    const [xml, installer, updater, acl, control] = await Promise.all([
      source("service/RadlinaRemoteMCP.xml"),
      source("scripts/operations/install-service.ps1"),
      source("scripts/operations/update-service.ps1"),
      source("scripts/operations/configure-service-acl.ps1"),
      source("scripts/operations/service-control.ps1"),
    ]);

    expect(xml).not.toMatch(/<serviceaccount>|<password>|<user>/i);
    expect(installer).toContain("configure-service-acl.ps1");
    expect(installer).toContain("migrate-dpapi-protection.ps1");
    expect(installer).toContain("StartName -ne 'LocalSystem'");
    expect(installer).not.toContain("install /p");
    expect(updater).toContain("config RadlinaRemoteMCP obj= LocalSystem");
    expect(updater).toContain("StartName -ne 'LocalSystem'");
    expect(acl).toContain("S-1-5-18");
    expect(acl).not.toContain("S-1-5-19");
    expect(control).toContain("identityIsTrustedOwner");
    expect(control).toContain("StartName -eq 'LocalSystem'");
  });

  it("uses machine DPAPI so the operator and LocalSystem share protected state", async () => {
    const dpapi = await source("src/auth/dpapi.ts");
    expect(dpapi).toContain("DataProtectionScope]::LocalMachine");
    expect(dpapi).not.toContain("DataProtectionScope]::CurrentUser");
  });
});
