# Endpoint identity and availability

OAuth resource identity, JWT audience, TLS certificates, ChatGPT connector configuration, and reconnect state all use one canonical HTTPS URL. Directly configuring several reserved IP addresses would make those identities ambiguous and would not make a single laptop highly available.

Tailscale Funnel already publishes the stable `*.ts.net` DNS name through multiple edge/relay addresses. Clients should resolve that hostname normally. IP addresses may change without changing the connector or token audience.

If a second ingress is added later, it must preserve the same hostname and TLS/OAuth resource identity through a reviewed load balancer or DNS failover design. A true second-device failover additionally requires replicated policy/state, exclusive session ownership, audit-chain fan-in, and a tested fencing mechanism; it is outside the single-device acceptance scope.
