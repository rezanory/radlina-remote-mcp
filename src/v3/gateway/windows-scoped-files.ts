/**
 * V3 native local Windows filesystem execution. This is NOT cross-device P06.
 * OAuth, exact physical device identity, safe roots and receipts are mandatory.
 */
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import type { AuthInfo } from "@modelcontextprotocol/server";
import type { AppConfig, WorkspaceProfile } from "../../config/schema.js";
import type { Store } from "../../persistence/store.js";
import { PolicyEngine } from "../../policy/engine.js";
import { FilesystemService } from "../../tools/filesystem/service.js";
import { ProcessManager } from "../../tools/process/manager.js";
import { SearchManager } from "../../tools/search/manager.js";
import { canonicalJson, sha256 } from "../../utils/json.js";
import { createWindowsPlatformAdapter } from "../device/windows-agent.js";
import type { SqliteDeviceRegistry } from "../device/registry.js";

const MAX_BYTES = 65536;
export const V3_WINDOWS_LOCAL_FILES_MODE = "local-windows-scoped-file-operations" as const;
export type WindowsFileWriteInput = {
  targetDeviceId: "windows-main";
  relativePath: string;
  content: string;
  overwrite: boolean;
  idempotencyKey: string;
};
export type WindowsFileReadInput = { targetDeviceId: "windows-main"; relativePath: string };

export class V3LocalFileDenied extends Error {
  constructor(message: string) {
    super(message);
    this.name = "V3LocalFileDenied";
  }
}

function ownerHash(auth: AuthInfo | undefined, scope: string): string {
  if (!auth?.scopes.includes(scope) || !auth.scopes.includes("device:read")) {
    throw new V3LocalFileDenied("separately approved V3 OAuth filesystem scope is required");
  }
  const sub = auth.extra?.["sub"];
  if (typeof sub !== "string" || !sub.trim() || !auth.clientId.trim()) {
    throw new V3LocalFileDenied("authenticated V3 OAuth owner and client are required");
  }
  return sha256(canonicalJson({ sub, client: auth.clientId }));
}
function boundedRelativePath(value: string): string {
  if (
    !value.trim() ||
    value.length > 1024 ||
    value.includes("\0") ||
    path.win32.isAbsolute(value) ||
    value.includes(":") ||
    /(^|[\\/])\.\.?([\\/]|$)/u.test(value)
  ) {
    throw new V3LocalFileDenied("only paths under the approved Windows root are permitted");
  }
  const result = path.win32.normalize(value);
  if (result === "." || result.startsWith("..")) {
    throw new V3LocalFileDenied("a regular relative path is required");
  }
  return result;
}

export class V3WindowsScopedFiles {
  readonly root: string;
  private readonly adapter: ReturnType<typeof createWindowsPlatformAdapter>;
  private readonly processes: ProcessManager;
  private readonly searches: SearchManager;

  constructor(
    private readonly config: AppConfig,
    private readonly store: Store,
    private readonly registry: SqliteDeviceRegistry,
    authorizedRoot: string,
    stateRoot: string,
  ) {
    if (process.platform !== "win32" || !path.win32.isAbsolute(authorizedRoot)) {
      throw new V3LocalFileDenied("V3 native Windows operations require an absolute Windows root");
    }
    this.root = path.win32.resolve(authorizedRoot);
    const profile: WorkspaceProfile = {
      roots: [this.root],
      commands: [],
      allowShell: false,
      allowTrash: false,
      envAllowlist: [],
    };
    const files = new FilesystemService(
      profile.roots,
      MAX_BYTES,
      path.join(stateRoot, "disabled-trash"),
      false,
    );
    const policy = new PolicyEngine(config, {
      killSwitch: () => true,
      emergencyReadOnly: () => true,
    });
    this.processes = new ProcessManager(config, store, policy);
    this.searches = new SearchManager(config, store);
    this.adapter = createWindowsPlatformAdapter({
      subject: "v3-scoped-file-owner",
      profileName: "v3-files",
      profile,
      filesystem: files,
      processes: this.processes,
      searches: this.searches,
      agentVersion: "3.0.0-alpha.1",
      readiness: async () => ({ ready: true, detail: "local V3 filesystem" }),
      scheduleRestart: async () => {
        throw new V3LocalFileDenied("restart is not a file operation");
      },
    });
    store.db.exec(
      "CREATE TABLE IF NOT EXISTS v3_scoped_file_operations (idempotency_key TEXT PRIMARY KEY,subject_hash TEXT NOT NULL,input_hash TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','completed')),result_json TEXT,created_at INTEGER NOT NULL,completed_at INTEGER)",
    );
  }

  private device(deviceId: string): void {
    const current = this.registry.get(deviceId);
    if (
      deviceId !== "windows-main" ||
      this.adapter.platform !== "windows" ||
      current?.trustState !== "trusted" ||
      current.platform !== "windows" ||
      current.hostname.toLowerCase() !== os.hostname().toLowerCase()
    ) {
      throw new V3LocalFileDenied("trusted local physical Windows identity mismatch");
    }
    if (this.config.policy.killSwitch || this.config.policy.emergencyReadOnly) {
      throw new V3LocalFileDenied("emergency policy denies V3 writes");
    }
  }
  private target(relativePath: string): string {
    return path.win32.join(this.root, boundedRelativePath(relativePath));
  }

  async write(input: WindowsFileWriteInput, auth: AuthInfo | undefined): Promise<unknown> {
    const owner = ownerHash(auth, "filesystem:write");
    this.device(input.targetDeviceId);
    const target = this.target(input.relativePath);
    const bytes = Buffer.from(input.content, "utf8");
    if (bytes.length > MAX_BYTES) throw new V3LocalFileDenied("64 KiB file limit exceeded");
    const hash = sha256(
      canonicalJson({
        device: input.targetDeviceId,
        path: target,
        bytes: sha256(bytes),
        overwrite: input.overwrite,
      }),
    );
    const existing = this.store.db
      .prepare(
        "SELECT subject_hash,input_hash,state,result_json FROM v3_scoped_file_operations WHERE idempotency_key=?",
      )
      .get(input.idempotencyKey) as
      | { subject_hash: string; input_hash: string; state: string; result_json: string | null }
      | undefined;
    if (existing) {
      if (existing.subject_hash !== owner || existing.input_hash !== hash) {
        throw new V3LocalFileDenied("idempotency key belongs to another input");
      }
      if (existing.state === "completed" && existing.result_json) {
        return JSON.parse(existing.result_json) as unknown;
      }
      throw new V3LocalFileDenied("write outcome uncertain; manual reconciliation required");
    }
    this.store.db
      .prepare(
        "INSERT INTO v3_scoped_file_operations(idempotency_key,subject_hash,input_hash,state,created_at) VALUES(?,?,?,'pending',?)",
      )
      .run(input.idempotencyKey, owner, hash, Date.now());

    await this.adapter.filesystem.writeFile(target, bytes, input.overwrite);
    const found = Buffer.from(await this.adapter.filesystem.readFile(target, 0, MAX_BYTES));
    const info = await this.adapter.filesystem.getFileInfo(target);
    if (info.kind !== "file" || info.size !== bytes.length || !found.equals(bytes)) {
      throw new V3LocalFileDenied("V3 Windows native file readback verification failed");
    }
    const outputHash = sha256(found);
    const receipt = {
      operationId: randomUUID(),
      targetDeviceId: "windows-main",
      mode: V3_WINDOWS_LOCAL_FILES_MODE,
      path: info.path,
      bytes: found.length,
      sha256: outputHash,
      readbackVerified: true,
      overwrite: input.overwrite,
      localAuditReceiptHash: sha256(
        canonicalJson({
          owner,
          inputHash: hash,
          device: "windows-main",
          outputHash,
        }),
      ),
      crossDeviceProductionAcceptance: false,
    };
    this.store.db
      .prepare(
        "UPDATE v3_scoped_file_operations SET state='completed',result_json=?,completed_at=? WHERE idempotency_key=? AND state='pending'",
      )
      .run(canonicalJson(receipt), Date.now(), input.idempotencyKey);
    return receipt;
  }

  async read(input: WindowsFileReadInput, auth: AuthInfo | undefined): Promise<unknown> {
    ownerHash(auth, "filesystem:read");
    this.device(input.targetDeviceId);
    const target = this.target(input.relativePath);
    const info = await this.adapter.filesystem.getFileInfo(target);
    if (info.kind !== "file" || info.size === null || info.size > MAX_BYTES) {
      throw new V3LocalFileDenied("only bounded regular files can be read");
    }
    const buffer = Buffer.from(await this.adapter.filesystem.readFile(target, 0, MAX_BYTES));
    return {
      targetDeviceId: "windows-main",
      mode: V3_WINDOWS_LOCAL_FILES_MODE,
      path: info.path,
      content: buffer.toString("utf8"),
      sha256: sha256(buffer),
      bytes: buffer.length,
    };
  }
  async close(): Promise<void> {
    await this.searches.shutdown();
    await this.processes.shutdown();
  }
}
