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
- All state paths (key, PID, DB) derive from `config.daemon.home` — never use hardcoded `DEFAULT_*` constants in daemon code
- Auto-starts when a bridge connects and no daemon is running

### Bridge (`mcp-guard connect --server <name>`)
- Contains: stdin/stdout relay to Unix socket, daemon.key authentication. Nothing else.
- **Zero policy logic. Zero upstream connection code.** If you're adding logic to the bridge, you're doing it wrong — put it in the daemon.
- Accepts `BridgeOptions` (socketPath, keyPath) from CLI — these are connection parameters, not policy logic
- If the daemon is unreachable, the bridge exits with a non-zero code (MCP client sees "server unavailable")

### CLI (`mcp-guard logs`, `status`, etc.)
- Stateless commands — talk to daemon for live data, read SQLite directly for historical queries
- No persistent state of their own

## Unix Socket Protocol

- Socket path: from `config.daemon.socket_path` (default: `~/.config/mcp-guard/daemon.sock`)
- Permissions: 0600 (owner-only)
- Protocol: length-prefixed JSON messages over the socket (4-byte big-endian uint32 length prefix)
- Authentication: Bridge sends daemon.key on connect; daemon verifies key (constant-time) + peer UID match

## Auto-Start Flow

1. Bridge checks if daemon is running (try connecting to socket at configured path)
2. If not running: `autoStartDaemon(configPath, socketPath)` forks and detaches a daemon process
3. Wait for socket to become available (poll configured socketPath, max ~3s)
4. Proceed with authentication
5. If auto-start fails: bridge exits non-zero (fail-closed)

## Graceful Shutdown

Shutdown uses a **single unified path** via `ShutdownHandle` returned by `registerShutdownHandlers()`. The `DaemonHandle.shutdown()` delegates to the same handle. Idempotency is guaranteed by promise caching — calling `shutdown()` multiple times returns the same promise.

Signal handlers use `process.once` (not `process.on`) to prevent listener accumulation in tests.

**Shutdown sequence:**
0. Pre-shutdown hooks run (config watcher stopped, dashboard HTTP server closed) — wrapped in try/catch so failures don't abort shutdown
1. SIGTERM/SIGINT received (or programmatic `shutdown()` called)
2. Socket server closed — sends `{ type: 'shutdown' }` to connected bridges
3. Upstream servers disconnected
4. SQLite WAL checkpointed and DB closed (try/catch — safe if already closed)
5. PID file removed
6. Signal handlers call `process.exit(0)` after completion (programmatic callers do not)

## Dashboard HTTP Server

- Binds to `127.0.0.1:{dashboard_port}` (port 0 = OS-assigned ephemeral port)
- Persists actual bound port to `{daemon.home}/dashboard.port` and auth token to `{daemon.home}/dashboard.token` (both 0600)
- `/healthz` — unauthenticated (for k8s liveness probes), returns `HealthResponse` JSON with 200/503
- `/api/status` — requires `Authorization: Bearer <token>`, constant-time token comparison via `timingSafeEqual`
- Token auto-generated via `randomBytes(32).toString('hex')` if not configured
- Health status logic: `healthy` (all servers connected + DB ok), `degraded` (some disconnected), `unhealthy` (DB error or no servers)
- `last_audit_write` tracked by audit tap, wired into health context

## DaemonHandle Interface

`startDaemon(config, configPath?)` returns `DaemonHandle`:
- `shutdown()` — trigger graceful shutdown
- `getDashboardPort()` — actual bound port (important when using port 0)
- `getDashboardToken()` — auth token for /api/status

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
