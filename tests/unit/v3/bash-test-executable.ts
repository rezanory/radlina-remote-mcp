import { existsSync } from "node:fs";
import path from "node:path";

/**
 * Windows ships a WSL launcher as "bash.exe", which fails in a SYSTEM service.
 * Prefer Git Bash for syntax-only checks, without weakening Mac runtime guards.
 */
export function bashForTest(): string {
  if (process.platform !== "win32") return "bash";
  const custom = process.env["RADLINA_TEST_BASH_PATH"];
  if (custom && existsSync(custom)) return custom;
  const roots = [
    process.env["ProgramFiles"],
    process.env["ProgramFiles(x86)"],
    "C:\\Program Files",
    "C:\\Program Files (x86)",
  ];
  for (const root of roots) {
    if (!root) continue;
    const exe = path.win32.join(root, "Git", "bin", "bash.exe");
    if (existsSync(exe)) return exe;
  }
  throw new Error("Native Git Bash is required for Windows Bash syntax tests; WSL launcher is not supported.");
}
