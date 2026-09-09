# Third-party sources and notices

## Incorporated runtime dependencies

- Model Context Protocol TypeScript SDK v2 packages `@modelcontextprotocol/server`, `@modelcontextprotocol/node`, `@modelcontextprotocol/express`, and test client `2.0.0`. Inspected source commit: `cc4b41617ce3601b1290d67216ea0b194a3cd9ac`. The repository is in an MIT-to-Apache-2.0 licensing transition; its license file governs individual contributions.
- MCP Inspector `2.5.0`, used as the official protocol inspection tool.
- WinSW `2.12.0`, MIT, release-tag commit `eef5bade59fca0254e387ac73ed7625ba6aa7147`.
- ripgrep `15.2.0`, release commit `e89fff89ac`, used as the bounded search engine.
- Node.js `24.20.0` LTS portable Windows runtime.
- Exact npm dependency versions and transitive licenses are generated into `reports/PH-01/licenses.json`.

Hashes and download origins are pinned in `third_party/runtime-manifest.json`.

## Reviewed and adapted as architectural references

- `wonderwhy-er/DesktopCommanderMCP`, MIT, inspected commit `56deabc3fe3c586f91728c56da5715712ff34eb6`. Its filesystem/search/process behavior informed capability parity. Its own security documentation correctly treats allowlists as guardrails, not a sandbox; this project implements an independent default-deny policy boundary.
- `desktop-commander/remote-desktop-commander`, inspected commit `b480501dcca59f802ebaf97f2f57b45252d0b720`. This public repository contains documentation/manifests; the hosted relay implementation is not open source and is not a project dependency.

## Deferred/reference-only projects

- `modelcontextprotocol/inspector`: official conformance UI/CLI; npm package is installed, source is not vendored.
- `supercorp-ai/supergateway`: prototype reference only, never the production security boundary.
- `cloudflare/workers-oauth-provider`: use only if a future Cloudflare issuer is selected.
- `PrefectHQ/fastmcp`: Python architecture reference only; this project remains one TypeScript stack.
- `microsoft/markitdown`: optional future document extraction after core acceptance.

No hosted Desktop Commander relay code, Supergateway server, FastMCP server, Cloudflare provider, or MarkItDown code is incorporated in this build.
