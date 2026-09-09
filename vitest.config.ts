import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    exclude: [".temp/**", "node_modules/**", "dist/**"],
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
