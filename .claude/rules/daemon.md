---
paths:
  - "src/daemon/**"
  - "src/bridge/**"
  - "src/proxy/**"
  - "src/storage/**"
  - "src/dashboard/**"
---

# Daemon & Bridge Rules

## Three Process Types

### Daemon (`mcp-guard start`)
- Long-running process, single instance per machine
- Owns: Unix socket server, all upstream MCP connections, SQLite database, interceptor pipeline, dashboard HTTP server
- PID file at `~/.config/mcp-guard/daemon.pid`
- Auto-starts when a bridge connects and no daemon is running

### Bridge (`mcp-guard connect --server <name>`)
- **Must stay ~50 lines of code**. This is a structural security guarantee.
- Contains: stdin/stdout relay to Unix socket, daemon.key authentication. Nothing else.
- **Zero policy logic. Zero upstream connection code.** If you're adding logic to the bridge, you're doing it wrong — put it in the daemon.
- If the daemon is unreachable, the bridge exits with a non-zero code (MCP client sees "server unavailable")

### CLI (`mcp-guard logs`, `status`, etc.)
- Stateless commands — talk to daemon for live data, read SQLite directly for historical queries
- No persistent state of their own

## Unix Socket Protocol

- Socket path: `~/.config/mcp-guard/daemon.sock`
- Permissions: 0600 (owner-only)
- Protocol: length-prefixed JSON messages over the socket
- Authentication: Bridge sends daemon.key on connect; daemon verifies key + peer UID match

## Auto-Start Flow

1. Bridge checks if daemon is running (try connecting to socket)
2. If not running: fork and detach a daemon process
3. Wait for socket to become available (poll, max ~2s)
4. Proceed with authentication
5. If auto-start fails: bridge exits non-zero (fail-closed)

## Graceful Shutdown

1. SIGTERM received → stop accepting new bridge connections
2. In-flight requests complete (configurable timeout, default 30s)
3. Bridges notified of shutdown via socket message
4. Audit log flushed and synced
5. SQLite WAL checkpointed
6. PID file removed
7. Daemon exits 0

## MCP Proxy Pattern

The daemon runs two MCP SDK instances per upstream server:
- **MCP Server** (client-facing): Receives messages from bridges, presents filtered capabilities
- **MCP Client** (upstream-facing): Sends inspected messages to upstream, handles responses

Messages flow: Bridge → Daemon MCP Server → Interceptor Pipeline → Daemon MCP Client → Upstream Server

## SQLite Conventions

- WAL mode always enabled for concurrent read/write
- Optional SQLCipher encryption (key derived from daemon.key)
- 0600 file permissions on database files
- Migrations run at daemon startup (forward-only, no down migrations)
- All queries use parameterized statements
