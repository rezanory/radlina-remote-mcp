import { lstat, realpath } from "node:fs/promises";
import path from "node:path";

import { AppError } from "../../errors.js";

const RESERVED = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

function contained(root: string, candidate: string): boolean {
  const normalizedRoot = path.win32
    .normalize(root)
    .replace(/[\\/]+$/u, "")
    .toLowerCase();
  const normalizedCandidate = path.win32.normalize(candidate).toLowerCase();
  return (
    normalizedCandidate === normalizedRoot || normalizedCandidate.startsWith(`${normalizedRoot}\\`)
  );
}

function rejectDangerousSyntax(input: string): void {
  if (!input || input.includes("\0"))
    throw new AppError("INVALID_PATH", "path is empty or contains a null byte");
  const normalized = input.replace(/\//gu, "\\");
  if (
    normalized.startsWith("\\\\") ||
    normalized.startsWith("\\\\?\\") ||
    normalized.startsWith("\\\\.\\")
  ) {
    throw new AppError("INVALID_PATH", "UNC and device paths are not allowed");
  }
  const rest = /^[A-Za-z]:/u.test(normalized) ? normalized.slice(2) : normalized;
  if (rest.includes(":"))
    throw new AppError("INVALID_PATH", "NTFS alternate data streams are not allowed");
  for (const segment of normalized.split("\\").filter(Boolean)) {
    if (RESERVED.test(segment) || /[. ]$/u.test(segment)) {
      throw new AppError("INVALID_PATH", "reserved or ambiguous Windows path segment");
    }
  }
}

export class SafePathResolver {
  constructor(private readonly roots: string[]) {}

  async resolve(input: string, options: { mustExist: boolean }): Promise<string> {
    rejectDangerousSyntax(input);
    const candidates = path.win32.isAbsolute(input)
      ? [path.win32.resolve(input)]
      : this.roots.map((root) => path.win32.resolve(root, input));
    for (const candidate of candidates) {
      const resolved = await this.resolveExistingAncestor(candidate, options.mustExist);
      for (const root of this.roots) {
        let canonicalRoot: string;
        try {
          canonicalRoot = await realpath(root);
        } catch {
          continue;
        }
        if (contained(canonicalRoot, resolved)) return resolved;
      }
    }
    throw new AppError("INVALID_PATH", "path escapes the configured workspace roots");
  }

  private async resolveExistingAncestor(candidate: string, mustExist: boolean): Promise<string> {
    try {
      await lstat(candidate);
      return await realpath(candidate);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      if (mustExist) throw new AppError("NOT_FOUND", "path does not exist");
    }
    const missing: string[] = [];
    let current = candidate;
    for (;;) {
      const parent = path.win32.dirname(current);
      if (parent === current)
        throw new AppError("INVALID_PATH", "no existing allowed ancestor was found");
      missing.unshift(path.win32.basename(current));
      current = parent;
      try {
        const canonicalParent = await realpath(current);
        return path.win32.join(canonicalParent, ...missing);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  }
}
