import { randomUUID } from "node:crypto";

export type ErrorCode =
  | "AUTH_REQUIRED"
  | "INSUFFICIENT_SCOPE"
  | "POLICY_DENIED"
  | "INVALID_PATH"
  | "NOT_FOUND"
  | "CONFLICT"
  | "LIMIT_EXCEEDED"
  | "INVALID_INPUT"
  | "SESSION_NOT_FOUND"
  | "INTERNAL_ERROR";

export class AppError extends Error {
  readonly correlationId: string;

  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "AppError";
    this.correlationId = randomUUID();
  }
}

export function errorPayload(error: unknown): {
  isError: true;
  content: [{ type: "text"; text: string }];
  structuredContent: Record<string, unknown>;
};
export function errorPayload(
  error: unknown,
  correlationId: string,
): {
  isError: true;
  content: [{ type: "text"; text: string }];
  structuredContent: Record<string, unknown>;
};
export function errorPayload(
  error: unknown,
  correlationId?: string,
): {
  isError: true;
  content: [{ type: "text"; text: string }];
  structuredContent: Record<string, unknown>;
} {
  const safe =
    error instanceof AppError
      ? {
          code: error.code,
          message: error.message,
          correlationId: correlationId ?? error.correlationId,
        }
      : {
          code: "INTERNAL_ERROR",
          message: "The operation failed",
          correlationId: correlationId ?? randomUUID(),
        };
  return {
    isError: true,
    content: [{ type: "text", text: `${safe.code}: ${safe.message} (${safe.correlationId})` }],
    structuredContent: safe,
  };
}
