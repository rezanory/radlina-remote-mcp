import { spawn } from "node:child_process";

import { AppError } from "../errors.js";

const PROTECT_SCRIPT = `
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$raw=[Convert]::FromBase64String([Console]::In.ReadToEnd())
$out=[Security.Cryptography.ProtectedData]::Protect($raw,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
[Console]::Out.Write([Convert]::ToBase64String($out))
`;

const UNPROTECT_SCRIPT = `
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$raw=[Convert]::FromBase64String([Console]::In.ReadToEnd())
$out=[Security.Cryptography.ProtectedData]::Unprotect($raw,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
[Console]::Out.Write([Convert]::ToBase64String($out))
`;

async function runPowerShell(script: string, input: string): Promise<string> {
  if (process.platform !== "win32") {
    if (process.env["NODE_ENV"] === "test") return input;
    throw new AppError("INTERNAL_ERROR", "DPAPI is only available on Windows");
  }
  return await new Promise((resolve, reject) => {
    const child = spawn(
      "powershell.exe",
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
      {
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve(stdout.trim());
      else
        reject(
          new AppError("INTERNAL_ERROR", "DPAPI operation failed", {
            exitCode: code,
            stderr: stderr.slice(0, 200),
          }),
        );
    });
    child.stdin.end(input);
  });
}

export async function protectBytes(value: Uint8Array): Promise<string> {
  return await runPowerShell(PROTECT_SCRIPT, Buffer.from(value).toString("base64"));
}

export async function unprotectBytes(value: string): Promise<Buffer> {
  const result = await runPowerShell(UNPROTECT_SCRIPT, value);
  return Buffer.from(result, "base64");
}
