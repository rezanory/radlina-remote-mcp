# Canonical Local Layout

The authoritative Windows root is:

`C:\radlina-remote-mcp`

All Radlina Remote MCP local operational material should live beneath this root.

## Tracked / runtime root

The production service currently executes:

`C:\radlina-remote-mcp\service\RadlinaRemoteMCP.exe`

For that reason the root itself is not relocated during canonicalization.

## Untracked local namespace

`C:\radlina-remote-mcp\.local\`

Subdirectories:

- `worktrees/primary`
- `worktrees/integration`
- `worktrees/governance`
- `evidence`
- `archives`
- `baselines`
- `candidates`
- `releases`
- `validation`
- `legacy`

No new root-level sibling matching `C:\radlina-remote-mcp-*` should be created.

`.local/` must be excluded from Git.

## Transitional migration exception

The authoritative V2 worktree is currently still physically located at:

`C:\\radlina-remote-mcp-worktrees\\v2-smart-operator-m01-20260911`

because an active Windows file lock prevents a safe `git worktree move`.
The canonical access path is already available as an NTFS junction at:

`C:\\radlina-remote-mcp\\.local\\worktrees\\primary\\v2-smart-operator-m01-20260911`

Do not force, delete, or manually copy this worktree. When the lock is gone, complete migration only with
`git worktree move`, then remove/replace the junction as appropriate and verify `git worktree list`.
