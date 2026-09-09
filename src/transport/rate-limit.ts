import type { NextFunction, Request, Response } from "express";
import type { AuthInfo } from "@modelcontextprotocol/server";

type Bucket = { tokens: number; updatedAt: number };

export function rateLimit(limitPerMinute: number) {
  const buckets = new Map<string, Bucket>();
  const refillPerMs = limitPerMinute / 60_000;
  return (request: Request, response: Response, next: NextFunction): void => {
    const key =
      (request as Request & { auth?: AuthInfo }).auth?.clientId ?? request.ip ?? "anonymous";
    const now = Date.now();
    const bucket = buckets.get(key) ?? { tokens: limitPerMinute, updatedAt: now };
    bucket.tokens = Math.min(
      limitPerMinute,
      bucket.tokens + (now - bucket.updatedAt) * refillPerMs,
    );
    bucket.updatedAt = now;
    if (bucket.tokens < 1) {
      response.setHeader("retry-after", "60");
      response.status(429).json({ error: "rate_limited" });
      return;
    }
    bucket.tokens -= 1;
    buckets.set(key, bucket);
    if (buckets.size > 1000) {
      for (const [itemKey, item] of buckets)
        if (now - item.updatedAt > 10 * 60_000) buckets.delete(itemKey);
    }
    next();
  };
}
