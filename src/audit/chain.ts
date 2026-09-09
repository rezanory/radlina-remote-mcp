import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { appendFile, mkdir, readFile, readdir, rename, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import type { AppConfig } from "../config/schema.js";
import { protectBytes, unprotectBytes } from "../auth/dpapi.js";
import type { Store } from "../persistence/store.js";
import { Redactor } from "./redaction.js";

export type AuditEvent = {
  correlationId: string;
  subject: string;
  deviceId: string;
  tool: string;
  args: unknown;
  decision: "allow" | "deny" | "error";
  durationMs: number;
  exitState: string;
  inputBytes?: number;
  outputBytes?: number;
};

type AuditRecord = AuditEvent & {
  timestamp: string;
  sequence: number;
  prevHash: string;
  hash: string;
};

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export class AuditChain {
  private key!: Buffer;
  private appendTail: Promise<void> = Promise.resolve();
  private readonly redactor: Redactor;
  private readonly activePath: string;

  constructor(
    private readonly config: AppConfig,
    private readonly store: Store,
  ) {
    this.redactor = new Redactor(config.audit.userRedactionPatterns);
    this.activePath = path.join(config.audit.directory, "audit.jsonl");
  }

  async initialize(): Promise<void> {
    await mkdir(this.config.audit.directory, { recursive: true });
    const keyPath = path.join(this.config.storage.directory, "audit-key.dpapi");
    try {
      this.key = await unprotectBytes((await readFile(keyPath, "utf8")).trim());
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      this.key = randomBytes(32);
      await writeFile(keyPath, await protectBytes(this.key), {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
    }
    const files = await this.files();
    const verification = await this.verify(files);
    if (!verification.valid) {
      throw new Error(
        `audit chain is invalid at sequence ${verification.firstInvalidSequence ?? "unknown"}`,
      );
    }
    let last: AuditRecord | undefined;
    for (const file of files) {
      try {
        const lines = (await readFile(file, "utf8")).split(/\r?\n/u).filter(Boolean);
        if (lines.length > 0) last = JSON.parse(lines.at(-1) ?? "") as AuditRecord;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    this.store.set("audit:sequence", String(last?.sequence ?? 0));
    this.store.set("audit:lastHash", last?.hash ?? "GENESIS");
  }

  async append(event: AuditEvent): Promise<AuditRecord> {
    const pending = this.appendTail.then(() => this.appendOne(event));
    this.appendTail = pending.then(
      () => undefined,
      () => undefined,
    );
    return pending;
  }

  private async appendOne(event: AuditEvent): Promise<AuditRecord> {
    await this.rotateIfNeeded();
    const sequence = Number(this.store.get("audit:sequence") ?? "0") + 1;
    const prevHash = this.store.get("audit:lastHash") ?? "GENESIS";
    const base = {
      ...event,
      args: this.redactor.value(event.args),
      timestamp: new Date().toISOString(),
      sequence,
      prevHash,
    };
    const hash = createHmac("sha256", this.key).update(canonical(base)).digest("hex");
    const record: AuditRecord = { ...base, hash };
    await appendFile(this.activePath, `${JSON.stringify(record)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    this.store.set("audit:sequence", String(sequence));
    this.store.set("audit:lastHash", hash);
    return record;
  }

  async verify(
    files: string[],
  ): Promise<{ valid: boolean; records: number; firstInvalidSequence?: number }> {
    let previous = "GENESIS";
    let records = 0;
    for (const file of files) {
      let content = "";
      try {
        content = await readFile(file, "utf8");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
      for (const line of content.split(/\r?\n/u).filter(Boolean)) {
        const record = JSON.parse(line) as AuditRecord;
        const { hash, ...base } = record;
        const expected = createHmac("sha256", this.key).update(canonical(base)).digest("hex");
        const equal =
          hash.length === expected.length &&
          timingSafeEqual(Buffer.from(hash), Buffer.from(expected));
        if (!equal || record.prevHash !== previous)
          return { valid: false, records, firstInvalidSequence: record.sequence };
        previous = hash;
        records += 1;
      }
    }
    return { valid: true, records };
  }

  async files(): Promise<string[]> {
    const names = await readdir(this.config.audit.directory);
    const rotated = names
      .filter((name) => /^audit-.+\.jsonl$/u.test(name))
      .sort()
      .map((name) => path.join(this.config.audit.directory, name));
    return [...rotated, this.activePath];
  }

  async recent(limit: number): Promise<AuditRecord[]> {
    const bounded = Math.min(Math.max(limit, 1), 200);
    const records: AuditRecord[] = [];
    for (const file of (await this.files()).reverse()) {
      let content: string;
      try {
        content = await readFile(file, "utf8");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
      const lines = content.split(/\r?\n/u).filter(Boolean).reverse();
      for (const line of lines) {
        records.push(JSON.parse(line) as AuditRecord);
        if (records.length >= bounded) return records;
      }
    }
    return records;
  }

  private async rotateIfNeeded(): Promise<void> {
    try {
      if ((await stat(this.activePath)).size < this.config.audit.rotateBytes) return;
      const suffix = new Date().toISOString().replace(/[:.]/gu, "-");
      await rename(
        this.activePath,
        path.join(this.config.audit.directory, `audit-${suffix}.jsonl`),
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}
