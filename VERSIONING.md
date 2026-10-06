# Radlina Remote MCP Versioning

Radlina Remote MCP uses independent version streams.

## Product stream

Source of runtime/product behavior.

Tag namespace:

`product/v<semver>`

Current proven baseline at creation of this policy:

`product/v2.0.0-alpha.2` → `df9d005c49e8f4ceb25105a81e33236f44543e54`

Future examples:

- `product/v3.0.0-alpha.1`
- `product/v3.0.0-beta.1`
- `product/v3.0.0`

Product SemVer is independent of workflow version.

## Workflow stream

Project governance and execution workflow.

Tag namespace:

`workflow/v<semver>`

Initial version:

`workflow/v1.0.0`

Workflow MAJOR: incompatible governance/authority semantics.
Workflow MINOR: additive normative rules or new governed capability class.
Workflow PATCH: clarification that does not change protected semantics.

## Release identity

A release receipt MUST record both:

- product version
- RRMW workflow version

and also:

- exact source commit
- tree SHA
- release manifest hash
- adopted CSEW exact version/hash

A workflow change does not force a product release.
A product change does not force a workflow bump unless governance semantics change.
