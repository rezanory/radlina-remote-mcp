import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { canonicalJson } from "../../utils/json.js";
import { parseDeviceDescriptor, type DeviceDescriptor } from "./identity.js";

export type DeviceHeartbeat = {
  lastSeen: string;
  status: DeviceDescriptor["status"];
  health: DeviceDescriptor["health"];
  agentVersion: string;
  capabilities: string[];
};

export class DeviceRegistryConflict extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeviceRegistryConflict";
  }
}

export class SqliteDeviceRegistry {
  readonly db: DatabaseSync;

  constructor(databaseFile: string) {
    mkdirSync(path.dirname(databaseFile), { recursive: true });
    this.db = new DatabaseSync(databaseFile, { enableForeignKeyConstraints: true });
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS v3_devices(
        device_id TEXT PRIMARY KEY,
        descriptor_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `);
  }

  register(rawDescriptor: DeviceDescriptor): { device: DeviceDescriptor; replayed: boolean } {
    const descriptor = parseDeviceDescriptor(rawDescriptor);
    const existing = this.get(descriptor.deviceId);
    if (existing) {
      this.assertStableIdentity(existing, descriptor);
      return { device: existing, replayed: true };
    }
    if (descriptor.trustState !== "pending") {
      throw new DeviceRegistryConflict("new device registration must start with pending trust");
    }
    const now = Date.now();
    this.db
      .prepare(
        "INSERT INTO v3_devices(device_id,descriptor_json,created_at,updated_at) VALUES(?,?,?,?)",
      )
      .run(descriptor.deviceId, canonicalJson(descriptor), now, now);
    return { device: descriptor, replayed: false };
  }

  get(deviceId: string): DeviceDescriptor | undefined {
    const row = this.db
      .prepare("SELECT descriptor_json FROM v3_devices WHERE device_id=?")
      .get(deviceId) as { descriptor_json: string } | undefined;
    return row ? parseDeviceDescriptor(JSON.parse(row.descriptor_json)) : undefined;
  }

  require(deviceId: string): DeviceDescriptor {
    const device = this.get(deviceId);
    if (!device) throw new DeviceRegistryConflict(`device ${deviceId} was not found`);
    return device;
  }

  list(): DeviceDescriptor[] {
    const rows = this.db
      .prepare("SELECT descriptor_json FROM v3_devices ORDER BY device_id ASC")
      .all() as Array<{ descriptor_json: string }>;
    return rows.map((row) => parseDeviceDescriptor(JSON.parse(row.descriptor_json)));
  }

  heartbeat(deviceId: string, heartbeat: DeviceHeartbeat): DeviceDescriptor {
    const existing = this.require(deviceId);
    const updated = parseDeviceDescriptor({
      ...existing,
      lastSeen: heartbeat.lastSeen,
      status: heartbeat.status,
      health: heartbeat.health,
      agentVersion: heartbeat.agentVersion,
      capabilities: heartbeat.capabilities,
    });
    const result = this.db
      .prepare("UPDATE v3_devices SET descriptor_json=?,updated_at=? WHERE device_id=?")
      .run(canonicalJson(updated), Date.now(), deviceId);
    if (Number(result.changes) !== 1) {
      throw new DeviceRegistryConflict("device heartbeat update failed");
    }
    return updated;
  }

  capabilities(deviceId: string): string[] {
    return [...this.require(deviceId).capabilities].sort();
  }

  close(): void {
    this.db.close();
  }

  private assertStableIdentity(existing: DeviceDescriptor, candidate: DeviceDescriptor): void {
    const fields = ["hostname", "platform", "architecture"] as const;
    for (const field of fields) {
      if (existing[field] !== candidate[field]) {
        throw new DeviceRegistryConflict(
          `device identity conflict for ${existing.deviceId}: ${field} changed`,
        );
      }
    }
  }
}
