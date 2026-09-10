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
);
