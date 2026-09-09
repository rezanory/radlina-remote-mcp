# ADR-002: Windows persistence mechanism

Status: Accepted with interactive installation gate

## Options

- Native Windows Service: best service semantics, but Node is not itself a Windows service binary and registration requires elevation.
- WinSW: good recovery and service identity controls, but adds a downloaded executable that must be version-pinned and checksum-verified.
- NSSM: mature wrapper, but another external executable with a larger operational trust decision.
- Scheduled Task: Windows-native, no extra binary, supports limited current-user execution and restart-at-logon; it does not provide full Service Control Manager semantics.

## Decision

Use WinSW 2.12.0 as a pinned Windows Service wrapper. The bootstrap verifies the exact SHA-256 of the official GitHub release asset before copying it into the service directory. Installation uses WinSW's local `/p` credential prompt and the existing low-privilege `Radlina` Windows account. The service must never use LocalSystem or an administrator account. No password is stored in XML, source, logs, or process arguments.

The Node server binds only to loopback. A dedicated inbound firewall block rule for the pinned Node executable provides defense in depth against a future bind-address mistake. Tailscale owns the HTTPS ingress separately.

## Consequences

WinSW configures automatic delayed start, bounded graceful shutdown, rotating logs, and restart-on-failure. Installation and firewall changes require one unavoidable UAC/credential interaction. Upgrade, uninstall, Tailscale restore, and retained-state rollback paths are explicit.
