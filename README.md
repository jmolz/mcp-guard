# MCP-Guard

[![CI](https://github.com/jmolz/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/jmolz/mcp-guard/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/mcp-guard)](https://www.npmjs.com/package/mcp-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Security proxy daemon for MCP servers — adds authentication, rate limiting, PII detection, permission scoping, and audit logging without modifying upstream servers.

## What is this?

MCP (Model Context Protocol) servers give AI coding tools access to files, databases, APIs, and more. But they have no built-in authentication, no audit trail, and no way to restrict which tools an agent can call.

MCP-Guard sits between your MCP client (Cursor, Claude Desktop, Claude Code, VS Code) and your MCP servers. It terminates the client connection, inspects every message through a security pipeline, then re-originates the request to the upstream server. Nothing passes through uninspected.

## Key Features

- **Authentication** — OS-level peer credentials, API keys, or OAuth 2.1 with PKCE
- **Rate limiting** — Per-server, per-user, per-tool limits with SQLite persistence
- **Permission scoping** — Allow/deny lists for tools and resources, with capability filtering
- **PII detection** — Regex-based scanning with Luhn validation, bidirectional (request + response)
- **Audit logging** — Every MCP interaction logged to queryable SQLite with optional encryption
- **Role-based policies** — OAuth claims mapped to roles with floor-based policy merge
- **Config composability** — Base configs via `extends` with SHA-256 pinning; personal configs can only restrict
- **Transport support** — stdio, SSE, and Streamable HTTP upstream connections
- **Zero-config start** — Daemon auto-starts on first bridge connection

## Quick Start

```bash
npm install -g @jacobmolz/mcpguard
```

### Option A: Auto-discover existing configs

```bash
mcp-guard init
```

This scans your Claude Desktop, Cursor, VS Code, and Claude Code configs, discovers MCP servers, and generates `mcp-guard.yaml`.

### Option B: Manual config

Create `mcp-guard.yaml`:

```yaml
servers:
  filesystem:
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
```

### Update your MCP client

Point your client at MCP-Guard instead of the upstream server:

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
                     Auth -> Rate Limit -> Permissions
                       -> Sampling Guard -> PII Detect
                                  |
                             Audit Tap
```

- **Daemon** — Long-running process. Manages upstream connections, runs the interceptor pipeline, owns the SQLite database, serves the health dashboard.
- **Bridge** — Thin stdio relay (~50 lines). Zero policy logic. Structurally fail-closed.
- **CLI** — Stateless commands for management and configuration.

### Security Model

MCP-Guard uses **terminate, inspect, re-originate** — it fully owns both the client and upstream connections. The interceptor pipeline is fail-closed: any error blocks the request. The audit tap is structural (wired outside the pipeline) and cannot be bypassed.

Config merge uses **floor-based semantics**: personal configs can restrict but never relax base policies. `allowed_tools` are intersected, `denied_tools` are unioned, rate limits take the stricter value.

## Benchmark Results

The benchmark suite tests against 4,500+ attack scenarios across 10 categories and 10,000+ legitimate requests.

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| Detection rate | 92.5% | >95% | In progress |
| False positive rate | 0.000% | <0.1% | Pass |
| p50 latency overhead | 0.19ms | <5ms | Pass |
| p99 latency overhead | 1.22ms | — | — |
| Throughput | 7,042 req/s | — | — |

### Per-Category Detection

| Category | Rate | Status |
|----------|------|--------|
| Permission bypass | 100% | Pass |
| PII response leak | 100% | Pass |
| Sampling injection | 100% | Pass |
| Config override | 100% | Pass |
| Capability probe | 96% | Pass |
| Resource traversal | 94% | In progress |
| Rate limit evasion | 92% | In progress |
| PII request leak | 84% | In progress |
| PII evasion | 82% | In progress |
| Auth bypass | 80% | In progress |

> Results from quick-mode stratified sample (1,004 scenarios). Full suite numbers may differ. Run `pnpm benchmark` for full results or see [latest report](benchmarks/results/REPORT.md) for charts.

## CLI Reference

| Command | Description |
|---------|-------------|
| `mcp-guard start` | Start daemon (foreground, or `-d` for background) |
| `mcp-guard stop` | Stop running daemon |
| `mcp-guard connect -s <name>` | Start bridge for a server |
| `mcp-guard init` | Generate config from existing MCP client configs |
| `mcp-guard status` | Show daemon status |
| `mcp-guard health` | Liveness check (exit code 0/1) |
| `mcp-guard validate` | Validate config file |
| `mcp-guard logs` | Query audit logs |
| `mcp-guard auth login` | OAuth 2.1 authentication |
| `mcp-guard auth status` | Show token status |
| `mcp-guard auth logout` | Remove stored tokens |
| `mcp-guard dashboard-token` | Display dashboard auth token |

## Configuration

See [`mcp-guard.example.yaml`](mcp-guard.example.yaml) for a complete example.

Key config sections:
- `servers` — Upstream MCP server definitions (command, args, env, transport, policy)
- `daemon` — Socket path, home directory, log level, dashboard port, encryption
- `auth` — Authentication mode (os, api_key, oauth) and role definitions
- `pii` — PII detection settings, custom types, per-type actions
- `audit` — Logging and retention settings

## Docker

```bash
docker build -f docker/Dockerfile -t mcp-guard .
docker run --rm mcp-guard --help
```

Or with docker-compose:

```bash
docker compose -f docker/docker-compose.yml up
```

## Development

```bash
pnpm install
pnpm dev              # Start in dev mode
pnpm test             # Run tests (360+ across 38 files)
pnpm lint             # Lint
pnpm typecheck        # Type check
pnpm build            # Production build
pnpm benchmark:quick  # Quick benchmark suite (~30s)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT
