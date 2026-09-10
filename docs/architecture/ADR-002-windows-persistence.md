# ADR-002: Windows persistence mechanism

Status: Superseded for trusted-owner production operation on 2026-09-10

## Options

- Native Windows Service: best service semantics, but Node is not itself a Windows service binary and registration requires elevation.
- WinSW: good recovery and service identity controls, but adds a downloaded executable that must be version-pinned and checksum-verified.
- NSSM: mature wrapper, but another external executable with a larger operational trust decision.
- Scheduled Task: Windows-native, no extra binary, supports limited current-user execution and restart-at-logon; it does not provide full Service Control Manager semantics.

## Decision

Use WinSW 2.12.0 as a pinned Windows Service wrapper. The bootstrap verifies the exact SHA-256 of the official GitHub release asset before copying it into the service directory. For the owner-authorized full-control deployment, installation uses the built-in `LocalSystem` account without a password. The project ACL preserves the existing owner and grants FullControl only to that owner, Administrators, and LocalSystem. Broad Users and Authenticated Users grants are rejected.

The Node server binds only to loopback. A dedicated inbound firewall block rule for the pinned Node executable provides defense in depth against a future bind-address mistake. Tailscale owns the HTTPS ingress separately.

## Consequences

WinSW configures automatic delayed start, bounded graceful shutdown, rotating logs, and restart-on-failure. LocalSystem materially increases impact if authorization is compromised, so loopback binding, OAuth, scopes, kill/read-only controls, manifest/path validation, durable idempotency, and the HMAC audit chain are mandatory defense-in-depth controls. Installation and firewall changes require one unavoidable UAC interaction. Upgrade, uninstall, Tailscale restore, and retained-state rollback paths are explicit.
