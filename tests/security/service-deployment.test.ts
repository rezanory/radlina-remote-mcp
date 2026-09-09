import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));

async function source(relativePath: string): Promise<string> {
  return await readFile(path.join(projectRoot, relativePath), "utf8");
}

describe("Windows service deployment boundary", () => {
  it("uses LocalService without a password prompt and applies ACL hardening", async () => {
    const [xml, installer, acl] = await Promise.all([
      source("service/RadlinaRemoteMCP.xml"),
      source("scripts/operations/install-service.ps1"),
      source("scripts/operations/configure-service-acl.ps1"),
    ]);

    expect(xml).toContain("<domain>NT AUTHORITY</domain>");
    expect(xml).toContain("<user>LocalService</user>");
    expect(xml).not.toMatch(/<password>|<user>LocalSystem<\/user>/i);
    expect(installer).toContain("configure-service-acl.ps1");
    expect(installer).toContain("migrate-dpapi-protection.ps1");
    expect(installer).not.toContain("install /p");
    expect(acl).toContain("S-1-5-19");
    expect(acl).toContain("workspace");
  });

  it("uses machine DPAPI so the operator and LocalService share protected state", async () => {
    const dpapi = await source("src/auth/dpapi.ts");
    expect(dpapi).toContain("DataProtectionScope]::LocalMachine");
    expect(dpapi).not.toContain("DataProtectionScope]::CurrentUser");
  });
});
