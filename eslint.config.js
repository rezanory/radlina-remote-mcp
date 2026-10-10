import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "reports/**",
      "evidence/**",
      ".state/**",
      ".runtime/**",
      ".temp/**",
      "eslint.config.js",
      "vitest.config.ts",
      "scripts/operations/license-inventory.mjs",
      "scripts/operations/build-release.mjs",
      "scripts/operations/closure-validation.mjs",
      "scripts/operations/isolated-upgrade-drill.mjs",
      "scripts/operations/verify-release.mjs",
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/no-confusing-void-expression": "off",
      "@typescript-eslint/no-magic-numbers": "off",
      "@typescript-eslint/require-await": "off",
    },
  },
  // Frozen historical acceptance fixture: a legacy untyped result list is intentionally
  // preserved as evidence. The waiver is scoped ONLY to this file, not runtime code.
  {
    files: ["scripts/acceptance/v3-wave4-runtime.ts"],
    rules: {
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
    },
  },
  // Protected V2 HTTP bootstrap uses a two-step self-referential MCP handler
  // initialization. Preserve the frozen runtime source; waive prefer-const only here.
  {
    files: ["src/http.ts"],
    rules: { "prefer-const": "off" },
  },
);
