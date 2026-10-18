import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";

import { AppError } from "../errors.js";
import type { Store } from "../persistence/store.js";
import { canonicalJson, sha256 } from "../utils/json.js";
import type { SafePathResolver } from "../tools/filesystem/safe-path.js";

export type RepeatGuardEvidence = {
  gate: string;
  operation: string;
  errorCode: string;
  candidateFiles: string[];
  stateFiles: string[];
};

const TOKEN = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/u;
const MAX_FILES = 16;
const MAX_ONE_FILE = 1_048_576;
const MAX_ALL_FILES = 4_194_304;

/** Match validation commands only. Read-only/status operations remain unaffected. */
export function isValidationCommand(executable: string, args: string[]): boolean {
  const base = path.win32.basename(executable).toLowerCase();
  const words = args.join(" ").toLowerCase();
  if (/\b(?:pytest|unittest|vitest|jest)\b/u.test(words)) return true;
  if (/\bmanage\.py\s+test(?:\s|$)/u.test(words)) return true;
  if (/^go(?:\.exe)?$/u.test(base) && args[0]?.toLowerCase() === "test") return true;
  if (/^(?:npm|npm\.cmd|pnpm|pnpm\.cmd)$/u.test(base) && args.includes("test")) return true;
  return false;
}

async function digestEvidence(files: string[], resolver: SafePathResolver): Promise<string> {
  if (!Array.isArray(files) || files.length === 0 || files.length > MAX_FILES)
    throw new AppError("INVALID_INPUT", "repeat guard evidence file count is invalid");
  const sorted = [...files].sort();
  if (new Set(sorted.map((name) => name.toLowerCase())).size !== sorted.length)
    throw new AppError("INVALID_INPUT", "repeat guard evidence files must be unique");
  let total = 0;
  const hash = createHash("sha256");
  for (const name of sorted) {
    const resolved = await resolver.resolve(name, { mustExist: true });
    const metadata = await stat(resolved);
    if (!metadata.isFile() || metadata.size > MAX_ONE_FILE || metadata.size < 0)
      throw new AppError("LIMIT_EXCEEDED", "repeat guard evidence file is invalid or oversized");
    total += metadata.size;
    if (total > MAX_ALL_FILES)
      throw new AppError("LIMIT_EXCEEDED", "repeat guard evidence aggregate exceeds limit");
    const content = await readFile(resolved);
    if (content.length !== metadata.size)
      throw new AppError("CONFLICT", "repeat guard evidence changed while being read");
    hash.update(canonicalJson([path.win32.normalize(resolved).toLowerCase(), content.length]));
    hash.update("\0");
    hash.update(content);
    hash.update("\0");
  }
  return hash.digest("hex");
}

export class ProcessRepeatGuard {
  constructor(private readonly store: Store) {
    this.store.db.exec(`
      CREATE TABLE IF NOT EXISTS process_repeat_claims (
        fingerprint TEXT PRIMARY KEY,
        subject_hash TEXT NOT NULL,
        profile TEXT NOT NULL,
        gate TEXT NOT NULL,
        command_hash TEXT NOT NULL,
        candidate_hash TEXT NOT NULL,
        state_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        UNIQUE(subject_hash,profile,gate,command_hash,candidate_hash,state_hash)
      );
    `);
  }

  async claim(
    subject: string,
    profile: string,
    executable: string,
    args: string[],
    cwd: string,
    env: Record<string, string> | undefined,
    evidence: RepeatGuardEvidence,
    resolver: SafePathResolver,
  ): Promise<{ fingerprint: string; claimed: true }> {
    if (![evidence.gate, evidence.operation, evidence.errorCode].every((v) => TOKEN.test(v)))
      throw new AppError("INVALID_INPUT", "repeat guard classification is invalid");
    const candidateHash = await digestEvidence(evidence.candidateFiles, resolver);
    const stateHash = await digestEvidence(evidence.stateFiles, resolver);
    const commandHash = sha256(canonicalJson({
      executable: path.win32.normalize(executable).toLowerCase(),
      args,
      cwd: path.win32.normalize(cwd).toLowerCase(),
      env: env ?? {},
    }));
    const subjectHash = sha256(subject);
    // Deliberately exclude operation/errorCode and idempotencyKey from the unique identity.
    const fingerprint = sha256(canonicalJson([
      subjectHash, profile, evidence.gate, commandHash, candidateHash, stateHash,
    ]));
    const result = this.store.db.prepare(`
      INSERT OR IGNORE INTO process_repeat_claims (
        fingerprint,subject_hash,profile,gate,command_hash,candidate_hash,state_hash,created_at
      ) VALUES (?,?,?,?,?,?,?,?)
    `).run(fingerprint, subjectHash, profile, evidence.gate, commandHash,
      candidateHash, stateHash, Date.now());
    if (Number(result.changes) !== 1)
      throw new AppError("CONFLICT", "unchanged validation already claimed; reconcile original attempt or establish changed evidence");
    return { fingerprint, claimed: true };
  }
}
