# ADR-001: Direct official MCP SDK on Express

Status: Accepted

## Context

The service is a security-sensitive, tool-only Windows daemon with no custom MCP Apps view. It needs direct control over bearer authentication, Host/Origin validation, request limits, session transport lifecycle, local control endpoints, and Windows persistence.

## Decision

Use TypeScript with the official MCP v2 split packages (`@modelcontextprotocol/server`, `@modelcontextprotocol/node`, and `@modelcontextprotocol/express`), Express, Zod, and JOSE. Do not retain the Skybridge React/view template because there is no UI and its view/build surface is unnecessary for this threat model. The design still follows the MCP app workflow for typed tools, structured content, annotations, OAuth discovery, and Streamable HTTP testing.

## Consequences

- Fewer runtime dependencies and no browser asset pipeline.
- Direct ownership of HTTP and authorization hardening.
- SDK changes require explicit compatibility tests and upgrade review.
