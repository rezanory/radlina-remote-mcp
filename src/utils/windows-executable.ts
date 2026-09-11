import { stat } from "node:fs/promises";
import path from "node:path";

export type ExecutableResolutionOptions = {
  cwd?: string;
  pathValue?: string;
  pathExtValue?: string;
};

function windowsEnvironment(name: string): string | undefined {
  const direct = process.env[name];
  if (direct !== undefined) return direct;
  const lowered = name.toLowerCase();
  for (const [key, value] of Object.entries(process.env)) {
    if (key.toLowerCase() === lowered) return value;
  }
  return undefined;
}

function executableNames(input: string, pathExtValue: string): string[] {
  if (path.win32.extname(input)) return [input];
  const extensions = pathExtValue
    .split(";")
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => (value.startsWith(".") ? value : `.${value}`));
  return [input, ...extensions.map((extension) => `${input}${extension}`)];
}

async function regularFile(candidate: string): Promise<boolean> {
  try {
    return (await stat(candidate)).isFile();
  } catch {
    return false;
  }
}

export async function resolveWindowsExecutable(
  input: string,
  options: ExecutableResolutionOptions = {},
): Promise<string | undefined> {
  const selected = input.trim();
  if (!selected || selected.includes("\0")) return undefined;

  const cwd = options.cwd ?? process.cwd();
  const pathValue = options.pathValue ?? windowsEnvironment("PATH") ?? "";
  const pathExtValue =
    options.pathExtValue ?? windowsEnvironment("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD";
  const hasSeparator = selected.includes("\\") || selected.includes("/");
  const candidates: string[] = [];

  if (path.win32.isAbsolute(selected)) {
    candidates.push(path.win32.normalize(selected));
  } else if (hasSeparator) {
    candidates.push(path.win32.resolve(cwd, selected));
  } else {
    const names = executableNames(selected, pathExtValue);
    for (const rawDirectory of pathValue.split(";")) {
      const directory = rawDirectory.trim().replace(/^"|"$/gu, "");
      if (!directory) continue;
      for (const name of names) candidates.push(path.win32.join(directory, name));
    }
  }

  const seen = new Set<string>();
  for (const candidate of candidates) {
    const normalized = path.win32.normalize(candidate);
    const key = normalized.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    if (await regularFile(normalized)) return normalized;
  }
  return undefined;
}
