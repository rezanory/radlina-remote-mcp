/**
 * Read-only, independent Windows Tailscale peer observation for the V3 P03
 * trust authority. Exact node identity hash is compared against trusted,
 * dual-signed registration; remote requests cannot supply or override it.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import os from "node:os";
import type { ObservedP03Peer } from "./i01-physical-session.js";

const DNS: Record<"macbook-main" | "windows-main", string> = {
  "macbook-main": "amirs-macbook-pro.taile17c9e.ts.net",
  "windows-main": "laptop-13qineif.taile17c9e.ts.net",
};
export class V3LiveTailnetNodeObserver implements ObservedP03Peer {
  observeExactTailnetNodeHash(deviceId: "macbook-main" | "windows-main"): string | undefined {
    if (process.platform !== "win32" || os.hostname().toLowerCase() !== "laptop-13qineif")
      return undefined;
    try {
      const raw = execFileSync("C:\\Program Files\\Tailscale\\tailscale.exe", ["status", "--json"], {
        windowsHide: true, encoding: "utf8", timeout: 12000, maxBuffer: 4 * 1024 * 1024,
      });
      const inventory = JSON.parse(raw) as {
        BackendState?: string; CurrentTailnet?: { Name?: string };
        Self?: { ID?: string; OS?: string; Online?: boolean; DNSName?: string };
        Peer?: Record<string, { ID?: string; OS?: string; Online?: boolean; DNSName?: string }>;
      };
      if (inventory.BackendState !== "Running" ||
        inventory.CurrentTailnet?.Name !== "rezanory.github") return undefined;
      const nodes = deviceId === "windows-main" ? [inventory.Self] : Object.values(inventory.Peer ?? {});
      const matches = nodes.filter(p =>
        p?.Online === true &&
        p.OS === (deviceId === "windows-main" ? "windows" : "macOS") &&
        p.DNSName?.replace(/\.$/u, "").toLowerCase() === DNS[deviceId] && p.ID);
      if (matches.length !== 1 || !matches[0]?.ID) return undefined;
      return createHash("sha256").update(matches[0].ID).digest("hex");
    } catch { return undefined; }
  }
}
