# ChatGPT connection

Prerequisites: local validation green, service running as low-privilege `Radlina`, Tailscale Funnel enabled, `config/local.yaml` updated to the exact Funnel HTTPS origin, and the service restarted.

1. Run `tailscale funnel status` and copy the exact `https://...ts.net` origin. Do not use an IP address.
2. In ChatGPT, open Settings, then Apps/Connectors, enable developer mode if required, and add a custom MCP connector with `<origin>/mcp`.
3. ChatGPT performs dynamic client registration and opens the authorization page. Review the client and requested scopes.
4. The page shows a non-secret request ID. On the laptop run:

   ```powershell
   & C:\radlina-remote-mcp\.runtime\node-v24.20.0-win-x64\node.exe C:\radlina-remote-mcp\dist\src\cli\control.js approve <request-id>
   ```

5. Refresh the authorization page. It redirects to ChatGPT with the one-time authorization code.
6. Test in order: `ping`, `who_am_i`, `list_directory`, then only the scopes and mutations intentionally approved.

Never paste passwords, tokens, authorization codes, private keys, recovery codes, or Tailscale keys into chat. The request ID alone is not a secret and cannot approve itself.

Emergency stop:

```powershell
& C:\radlina-remote-mcp\.runtime\node-v24.20.0-win-x64\node.exe C:\radlina-remote-mcp\dist\src\cli\control.js kill on
```

Rollback public exposure by running `scripts\operations\restore-tailscale.ps1`, which restores the exact pre-change Tailscale serving configuration snapshot.
