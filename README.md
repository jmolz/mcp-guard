# MCP-Guard

Security proxy daemon for MCP servers — adds authentication, rate limiting, PII detection, and audit logging without modifying upstream servers.

## What is this?

MCP (Model Context Protocol) servers give AI coding tools access to files, databases, APIs, and more. But they have no built-in authentication, no audit trail, and no way to restrict which tools an agent can call.

MCP-Guard sits between your MCP client (Cursor, Claude Desktop, Claude Code, VS Code) and your MCP servers. It terminates the client connection, inspects every message through a security pipeline, then re-originates the request to the upstream server. Nothing passes through uninspected.

## Quick Start

```bash
npm install -g mcp-guard
```

Create `mcp-guard.yaml`:

```yaml
servers:
  filesystem:
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
```

Update your MCP client config to point at MCP-Guard:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-guard",
      "args": ["connect", "--server", "filesystem"]
    }
  }
}
```

The daemon auto-starts on first connection.

## Architecture

```
Client -> Bridge (stdio) -> Daemon (Unix socket) -> Upstream MCP Server
                                  |
                            Interceptor Pipeline
                            (Auth, Rate Limit, Permissions, PII)
                                  |
                             Audit Tap
```

- **Daemon** — Long-running process. Manages upstream connections, runs security pipeline, owns the database.
- **Bridge** — Thin stdio relay (~50 lines). Zero policy logic. Structurally fail-closed.
- **CLI** — Stateless commands for management.

## CLI Reference

| Command | Description |
|---------|-------------|
| `mcp-guard start` | Start daemon (foreground, or `-d` for background) |
| `mcp-guard stop` | Stop running daemon |
| `mcp-guard connect -s <name>` | Start bridge for a server |
| `mcp-guard status` | Show daemon status |
| `mcp-guard health` | Liveness check (exit code 0/1) |
| `mcp-guard validate` | Validate config file |

## Configuration

See `mcp-guard.example.yaml` for a complete example.

## Development

```bash
pnpm install
pnpm dev          # Start in dev mode
pnpm test         # Run tests
pnpm lint         # Lint
pnpm typecheck    # Type check
pnpm build        # Production build
```

## License

MIT
