const SECRET_KEYS =
  /authorization|token|secret|password|passwd|private.?key|connection.?string|cookie|api.?key/i;
const SECRET_VALUES = [
  /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  /(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{16,}/g,
  /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^\s]+/gi,
];

export class Redactor {
  private readonly userPatterns: RegExp[];

  constructor(patterns: string[]) {
    this.userPatterns = patterns.map((pattern) => new RegExp(pattern, "gi"));
  }

  text(value: string): string {
    let result = value;
    for (const pattern of [...SECRET_VALUES, ...this.userPatterns])
      result = result.replace(pattern, "[REDACTED]");
    return result;
  }

  value(value: unknown, depth = 0): unknown {
    if (depth > 8) return "[TRUNCATED_DEPTH]";
    if (typeof value === "string") return this.text(value).slice(0, 4096);
    if (Array.isArray(value)) return value.slice(0, 100).map((item) => this.value(item, depth + 1));
    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>).map(([key, item]) => [
          key,
          SECRET_KEYS.test(key) ? "[REDACTED]" : this.value(item, depth + 1),
        ]),
      );
    }
    return value;
  }
}
