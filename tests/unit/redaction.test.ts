import { describe, expect, it } from "vitest";

import { Redactor } from "../../src/audit/redaction.js";

describe("Redactor", () => {
  it("redacts secret-bearing keys and values recursively", () => {
    const redactor = new Redactor(["custom-[0-9]+"]);
    const result = redactor.value({
      authorization: "Bearer abc.def.ghi",
      nested: { apiKey: "top-secret", note: "custom-123 and Bearer token-value" },
    });
    expect(result).toEqual({
      authorization: "[REDACTED]",
      nested: { apiKey: "[REDACTED]", note: "[REDACTED] and [REDACTED]" },
    });
  });
});
