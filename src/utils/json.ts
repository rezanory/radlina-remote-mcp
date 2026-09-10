import { createHash } from "node:crypto";

export function canonicalJson(value: unknown): string {
  if (value === undefined) return "null";
  if (Array.isArray(value))
    return `[${value.map((item) => canonicalJson(item === undefined ? null : item)).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function encodeCursor(value: Record<string, unknown>): string {
  return Buffer.from(canonicalJson(value), "utf8").toString("base64url");
}

export function decodeCursor<T>(cursor: string): T {
  return JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as T;
}
