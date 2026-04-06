# Product Requirements Document: MCP-Guard

## Executive Summary

MCP-Guard is a security proxy daemon that sits between MCP clients (Cursor, Claude Desktop, Claude Code, VS Code, etc.) and MCP servers, adding OAuth 2.1 authentication, rate limiting, request/response logging, PII detection, and permission scoping to *any* MCP server — without modifying it.

It operates on a **terminate, inspect, re-originate** architecture: MCP-Guard fully terminates the client connection (running its own MCP Server), applies a security interceptor pipeline, then re-originates the request as an MCP Client to the upstream server. Nothing passes through uninspected. The upstream server never talks to the client directly.

MCP-Guard runs as a persistent daemon with auto-start capability. MCP clients spawn thin bridge processes that connect to the daemon via an authenticated Unix socket. The bridge contains zero policy logic and zero upstream connection code — it is structurally incapable of bypassing the daemon. This is the "security guard at the door" model: you explicitly point your MCP client at MCP-Guard, and MCP-Guard enforces your policies.

**MVP Goal:** A production-grade security proxy daemon that transparently intercepts all MCP message types across stdio and SSE transports, with authentication, rate limiting, permission scoping, PII detection, and audit logging — usable by solo developers with zero config and by enterprise teams with full policy composability.

---

## Target Users

### Primary Persona: Solo Developer

- **Who:** Individual engineer using MCP servers with AI coding tools (Cursor, Claude Code, VS Code)
- **Technical Level:** Developer
- **Key Need:** Add security and logging to MCP servers without modifying them or changing workflows
- **Pain Point:** MCP servers have no authentication, no audit trail, no way to restrict which tools an agent can call

### Secondary Persona: Platform / Security Engineer

- **Who:** Engineer responsible for approving and securing MCP server usage across a team or organization
- **Technical Level:** Developer / DevOps
- **Key Need:** Centralized security policy enforcement, compliance-ready audit trails, PII protection
- **Pain Point:** No way to enforce org-wide security policies on MCP servers; each developer configures servers independently with no oversight

### Tertiary Persona: MCP Server Developer

- **Who:** Developer building or maintaining MCP servers
- **Technical Level:** Developer
- **Key Need:** Test security posture of their MCP server against known attack vectors
- **Pain Point:** No tooling exists to audit MCP servers for vulnerabilities

---

## MVP Scope

### In Scope

✅ **Core Architecture**
- [ ] Persistent daemon with auto-start on first bridge connection
- [ ] Thin stdio bridge process spawned by MCP clients (~50 lines, zero policy logic)
- [ ] Authenticated daemon channel (daemon.key, Unix socket 0600, peer credential verification (SO_PEERCRED on Linux, getpeereid()+LOCAL_PEERPID on macOS via koffi))
- [ ] Structurally fail-closed bridge (no upstream connection code exists in the bridge)
- [ ] Full MCP Server facing client, full MCP Client facing upstream (terminate/inspect/re-originate)
- [ ] Support for all MCP message types: tools/call, tools/list, resources/read, resources/list, prompts/get, sampling/createMessage, notifications, initialize
- [ ] Capability filtering on initialize (denied tools/resources removed from capability advertisement)
- [ ] Stdio and SSE transport support for upstream servers

✅ **Security Interceptor Pipeline**
- [ ] Fixed-order interceptor chain: Auth → RateLimit → Permissions → PII Detect → [upstream] → PII Detect → [client]
- [ ] Structural audit tap (observes everything, cannot be skipped/disabled/blocked)
- [ ] Three decisions: PASS, MODIFY, BLOCK
- [ ] Fail-closed on interceptor throw or timeout
- [ ] Per-interceptor configurable timeout (default 10s, default action: block)
- [ ] Custom/plugin interceptors run after built-ins, scoped to params/content only (cannot modify tool names or methods)

✅ **Authentication & Identity**
- [ ] OS-level identity via peer credential verification (SO_PEERCRED on Linux, getpeereid()+LOCAL_PEERPID on macOS via koffi) (zero-config default)
- [ ] Token/OAuth 2.1 authentication (enterprise mode)
- [ ] Role-based permission mapping
- [ ] `mcp-guard auth login/status/logout` CLI flow
- [ ] API key validation for simpler setups
- [ ] Per-server auth configuration

✅ **Rate Limiting**
- [ ] Token bucket rate limiter
- [ ] Persistent to SQLite (survives daemon restarts)
- [ ] Configurable per server, per tool, per user/role
- [ ] Cross-server rate limits (enabled by daemon architecture)
- [ ] RateLimitStore interface for plugging in Redis/external stores

✅ **Permission Scoping**
- [ ] Allow/deny lists for MCP tools per server
- [ ] Allow/deny lists for MCP resources per server
- [ ] Wildcard and regex support for tool/resource matching
- [ ] Role-based access control: different users get different permissions
- [ ] Sampling/createMessage policy (disabled by default — fail-closed)
- [ ] Capability filtering: denied tools/resources removed from server capability response

✅ **PII Detection**
- [ ] Pluggable detector interface (PIIDetector)
- [ ] Built-in regex detector: emails, phone numbers, SSNs, credit cards (Luhn-validated), AWS keys, GitHub tokens, high-entropy strings
- [ ] Directional actions: separate request vs. response actions per PII type
- [ ] Three actions: redact, warn, block
- [ ] Custom PII types definable in config (enterprise: MRNs, project codenames, etc.)
- [ ] Confidence scoring with configurable threshold
- [ ] Buffered response scanning by default (streaming opt-in with sliding window)
- [ ] Redacted values never stored in audit log

✅ **Audit Logging**
- [ ] SQLite storage with WAL mode for concurrent access
- [ ] Encryption at rest via SQLCipher (optional, key derived from daemon.key)
- [ ] 0600 file permissions on database
- [ ] Every request/response logged: timestamp, direction, server, tool/resource, parameters (redacted if PII), result status, latency, identity, interceptor decisions
- [ ] Structured JSON logs to stdout for container deployments (alongside SQLite)
- [ ] CLI query interface: `mcp-guard logs --server X --last 1h --export csv`
- [ ] Log retention policies (configurable, default 90 days)

✅ **Configuration**
- [ ] YAML-based declarative config (mcp-guard.yaml)
- [ ] Zod schema validation at daemon startup (invalid config = refuse to start)
- [ ] `extends` with SHA-256 hash pinning for base policy inheritance
- [ ] Floor-based merge semantics: personal configs can only restrict, not relax base policies
- [ ] `locked: true` policies in base config prevent any override
- [ ] Environment variable interpolation (${VAR_NAME})
- [ ] Hot reload for policy changes (server definition changes require graceful restart of affected connections)
- [ ] `mcp-guard validate` checks config without starting

✅ **CLI Interface**
- [ ] `mcp-guard start` — start daemon (also auto-starts on first bridge connect)
- [ ] `mcp-guard stop` — graceful daemon shutdown
- [ ] `mcp-guard connect --server <name>` — thin bridge (spawned by MCP clients)
- [ ] `mcp-guard status` — daemon health, connected bridges, upstream server status
- [ ] `mcp-guard health` — liveness check (exit code 0/1)
- [ ] `mcp-guard logs` — query audit logs with filtering and export
- [ ] `mcp-guard validate` — validate config file
- [ ] `mcp-guard auth login/status/logout` — identity management
- [ ] `mcp-guard init` — generate mcp-guard.yaml from existing client configs, print instructions (does NOT rewrite client configs)
- [ ] `mcp-guard dashboard-token` — display dashboard auth token

✅ **Dashboard**
- [ ] Web UI on configurable port (default 9777, bound to 127.0.0.1)
- [ ] Authenticated by default (token generated on first run)
- [ ] Real-time proxy status, request/response timeline, PII alerts, rate limit status
- [ ] Health endpoint at /healthz for monitoring systems
- [ ] Built with simple HTML + htmx

✅ **Operational**
- [ ] Graceful shutdown: in-flight requests complete (configurable timeout, default 30s), bridges notified, audit log flushed, SQLite WAL checkpointed
- [ ] Health check endpoint (HTTP /healthz + CLI `mcp-guard health`)
- [ ] Daemon uptime, connection counts, upstream status, last audit write

✅ **Distribution**
- [ ] npm package: `npx mcp-guard start`
- [ ] Docker image: `ghcr.io/jmolz/mcp-guard`
- [ ] launchd/systemd integration for auto-start on boot

### Out of Scope

❌ Auto-rewriting MCP client configs (`mcp-guard init` generates config and prints instructions, never touches client files)
❌ Building a full identity provider (integrates with existing OAuth providers)
❌ Modifying MCP server code (transparent proxy)
❌ Building an MCP client (proxies between existing clients and servers)
❌ MCP server security scanner (`mcp-guard scan` — deferred to post-MVP)
❌ Threat detection / anomaly detection (prompt injection detection, confused deputy detection — deferred to post-MVP)
❌ External log sinks (Elasticsearch, Datadog, Splunk, OTLP — deferred to post-MVP, stdout JSON covers container use cases)
❌ Multi-machine clustering (single-daemon deployment only for MVP)
❌ LLM-based PII detection (ships as pluggable detector, not built-in for MVP)

---

## User Stories

1. As a **solo developer**, I want to install MCP-Guard and have it work with my existing MCP servers by changing one line in my client config, so that I get security without friction.
2. As a **developer**, I want all my MCP interactions logged to a queryable audit trail, so that I can understand what tools my AI agent is calling and with what parameters.
3. As a **security engineer**, I want to publish a base security policy that my entire team inherits, with restrictions that individual developers cannot relax, so that I can enforce org-wide MCP security standards.
4. As a **developer**, I want to deny specific dangerous tools (delete_repo, execute_sql, drop_table) while allowing all others, so that my AI agent can't accidentally cause damage.
5. As a **security engineer**, I want PII detected and redacted from MCP traffic before it reaches upstream servers, so that sensitive data doesn't leak to third-party services.
6. As a **developer**, I want rate limits on MCP tool calls so that a runaway AI agent can't exhaust API quotas or overwhelm a service.
7. As a **security engineer**, I want to block MCP servers from using sampling/createMessage to inject prompts into the user's LLM, so that compromised servers can't manipulate agents.
8. As a **developer**, I want the proxy to be invisible — my MCP client shouldn't know or care that MCP-Guard is in the middle, and denied tools shouldn't even appear in the tool list.
9. As a **platform engineer**, I want structured JSON logs on stdout so that MCP-Guard works with our existing log aggregation pipeline in Kubernetes.
10. As a **developer**, I want to see real-time proxy status, PII detection alerts, and rate limit state in a web dashboard without setting up external monitoring.

---

## Tech Stack

| Technology | Purpose | Version |
|------------|---------|---------|
| TypeScript (Node.js) | Core proxy, daemon, CLI, bridge | Node 22+ |
| @modelcontextprotocol/sdk | MCP Server + Client instances | Latest |
| Commander.js | CLI framework | Latest |
| js-yaml + zod | YAML config parsing + type-safe validation | Latest |
| jose | JWT validation for OAuth 2.1 | Latest |
| oauth4webapi | OAuth 2.1 token introspection | Latest |
| better-sqlite3-multiple-ciphers | Audit logs, rate limit state, sessions (drop-in better-sqlite3 replacement with built-in encryption support) | Latest |
| koffi | Unix socket peer credential verification (FFI, no compilation) | Latest |
| htmx | Dashboard web UI | Latest |
| tsup | Build/bundling | Latest |
| vitest | Testing | Latest |
| Python (matplotlib/seaborn) | Benchmark chart generation | 3.12+ |
| Docker | Container distribution | Latest |

---

## Architecture

### System Diagram

```
┌──────────────┐         ┌─────────────────────────────────────────────────────┐
│  MCP Client  │         │              MCP-Guard Daemon                       │
│  (Cursor,    │  stdio  │                                                     │
│   Claude,    │◀───────▶│  ┌─────────┐    ┌──────────────────┐    ┌────────┐ │
│   VS Code)   │         │  │  Thin   │unix│                  │    │Upstream│ │
│              │         │  │  Bridge │sock│   Interceptor    │    │  MCP   │ │
└──────────────┘         │  │         │◀──▶│   Pipeline       │◀──▶│ Client │ │
                         │  │ (per    │    │                  │    │(per    │ │
                         │  │  server)│    │                  │    │ server)│ │
                         │  └─────────┘    └──────────────────┘    └────────┘ │
                         │       ▲                  │                    │     │
                         │       │            ┌─────┴──────┐       ┌────┴───┐ │
                         │  ┌────┴─────┐      │ Audit Tap  │       │Upstream│ │
                         │  │ Identity │      │ (structural│       │  MCP   │ │
                         │  │ Manager  │      │  observer) │       │ Server │ │
                         │  └──────────┘      └─────┬──────┘       │(child  │ │
                         │                          │              │proc or │ │
                         │  ┌──────────┐      ┌─────┴──────┐       │ SSE)   │ │
                         │  │ Config   │      │  SQLite    │       └────────┘ │
                         │  │ Manager  │      │ (audit,    │                  │
                         │  └──────────┘      │  rate lim, │                  │
                         │                    │  sessions) │                  │
                         │  ┌──────────┐      └────────────┘                  │
                         │  │Dashboard │                                      │
                         │  │ (HTTP)   │                                      │
                         │  └──────────┘                                      │
                         └─────────────────────────────────────────────────────┘
```

### Three Process Types

1. **Daemon** (`mcp-guard start`) — Long-running process. Manages all upstream MCP server connections, runs the interceptor pipeline, owns the SQLite database, serves the dashboard. Auto-starts on first bridge connection if not already running.

2. **Bridge** (`mcp-guard connect --server <name>`) — Thin process spawned by MCP clients. Bridges client stdio to the daemon via authenticated Unix socket. Contains zero policy logic and zero upstream connection code. Structurally incapable of bypassing the daemon. ~50 lines of code.

3. **CLI** (`mcp-guard logs`, `mcp-guard status`, etc.) — Talks to the daemon for live data, reads SQLite directly for historical queries. Stateless.

### Directory Structure

```
mcp-guard/
├── src/
│   ├── daemon/                  # Daemon process
│   │   ├── index.ts             # Daemon entry point and lifecycle
│   │   ├── server-manager.ts    # Manages upstream MCP server connections
│   │   ├── socket-server.ts     # Unix socket server for bridge connections
│   │   ├── auto-start.ts        # Auto-start logic (fork + detach)
│   │   └── shutdown.ts          # Graceful shutdown handler
│   ├── bridge/                  # Thin bridge process
│   │   ├── index.ts             # Bridge entry point (~50 lines)
│   │   └── auth.ts              # Daemon authentication
│   ├── proxy/                   # MCP protocol handling
│   │   ├── mcp-server.ts        # MCP Server instance (faces client)
│   │   ├── mcp-client.ts        # MCP Client instance (faces upstream)
│   │   ├── capability-filter.ts # Filters capabilities based on policies
│   │   └── message-router.ts    # Routes messages through interceptor pipeline
│   ├── interceptors/            # Interceptor pipeline
│   │   ├── pipeline.ts          # Pipeline runner with timeout + fail-closed
│   │   ├── types.ts             # Interceptor interface, Decision type, contexts
│   │   ├── auth.ts              # Authentication interceptor
│   │   ├── rate-limit.ts        # Rate limiting interceptor
│   │   ├── permissions.ts       # Permission scoping interceptor
│   │   ├── pii-detect.ts        # PII detection interceptor
│   │   └── sampling-guard.ts    # Sampling/createMessage policy
│   ├── pii/                     # PII detection system
│   │   ├── detector.ts          # PIIDetector interface
│   │   ├── regex-detector.ts    # Built-in regex detector
│   │   ├── registry.ts          # Detector registry and execution
│   │   └── redactor.ts          # Redaction logic
│   ├── audit/                   # Audit logging
│   │   ├── tap.ts               # Structural audit tap
│   │   ├── store.ts             # SQLite audit storage
│   │   ├── query.ts             # Audit log query engine
│   │   └── stdout-logger.ts     # Structured JSON stdout logger
│   ├── identity/                # Identity and auth
│   │   ├── os-identity.ts       # peer credential verification (SO_PEERCRED on Linux, getpeereid()+LOCAL_PEERPID on macOS via koffi) identity resolution
│   │   ├── token-auth.ts        # OAuth 2.1 / token authentication
│   │   ├── roles.ts             # Role resolution and permission mapping
│   │   └── daemon-key.ts        # Daemon key generation and verification
│   ├── config/                  # Configuration system
│   │   ├── schema.ts            # Zod schema definitions
│   │   ├── loader.ts            # YAML loading with extends resolution
│   │   ├── merger.ts            # Floor-based merge semantics
│   │   ├── validator.ts         # Config validation
│   │   └── watcher.ts           # Hot reload file watcher
│   ├── storage/                 # Database layer
│   │   ├── sqlite.ts            # SQLite connection with WAL + optional SQLCipher
│   │   ├── migrations.ts        # Schema migrations
│   │   └── rate-limit-store.ts  # RateLimitStore interface + SQLite implementation
│   ├── dashboard/               # Web dashboard
│   │   ├── server.ts            # HTTP server with auth
│   │   ├── health.ts            # /healthz endpoint
│   │   └── views/               # HTML + htmx templates
│   └── cli.ts                   # CLI entry point (Commander.js)
├── benchmarks/
│   ├── security/
│   │   ├── scenarios/           # 10 attack categories, 450+ scenarios each
│   │   ├── mock-servers/        # 8-10 purpose-built mock MCP servers
│   │   ├── legitimate-traffic/  # Benign traffic baseline for false positive measurement
│   │   └── run.py               # Orchestrator
│   ├── performance/
│   │   ├── load_test.py         # 10K requests, latency measurement
│   │   ├── concurrency_test.py  # 1/10/50/100 concurrent connections
│   │   └── baseline_test.py     # Direct-to-server baseline
│   ├── compatibility/
│   │   ├── test_servers.py      # Tier 2/3 server testing
│   │   └── server_matrix.json   # Server list and configs
│   ├── results/                 # Raw JSON results (committed)
│   ├── charts/                  # Generated SVGs (committed)
│   ├── generate_charts.py       # Results → SVG charts
│   └── generate_tables.py       # Results → markdown tables
├── docker/
│   ├── Dockerfile               # Production image
│   ├── Dockerfile.dev           # Dev image with hot reload
│   └── docker-compose.yml       # MCP-Guard + example MCP servers
├── .github/
│   ├── workflows/
│   │   ├── ci.yml               # Lint, typecheck, test on push/PR
│   │   ├── release.yml          # Build + publish on tag push (npm + Docker + GitHub Release)
│   │   ├── benchmarks.yml       # Run benchmarks on demand
│   │   └── security.yml         # CodeQL + dependency scanning weekly
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   ├── feature_request.yml
│   │   └── security_vulnerability.yml
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── dependabot.yml
│   └── CODEOWNERS
├── tsconfig.json
├── vitest.config.ts
├── package.json
├── pnpm-lock.yaml
├── CLAUDE.md
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE                      # MIT
└── README.md
```

### Data Flow

**Request path:**
1. MCP client spawns `mcp-guard connect --server supabase` as a child process
2. Bridge checks if daemon is running; auto-starts it if not
3. Bridge authenticates to daemon via daemon.key over Unix socket
4. Bridge forwards client's stdio messages to daemon
5. Daemon's MCP Server instance receives the message
6. Audit tap records the raw request
7. Interceptor pipeline runs in fixed order: Auth → RateLimit → Permissions → PII Detect
8. If any interceptor returns BLOCK (or throws/times out): error returned to client, audit tap records the block
9. If all interceptors PASS/MODIFY: daemon's MCP Client sends the (possibly modified) message to upstream server
10. Upstream response received
11. Response-side interceptors run: PII Detect (buffered)
12. Audit tap records the response
13. Response returned to client via bridge

**Capability negotiation:**
1. Client sends `initialize` — daemon intercepts
2. Daemon forwards to upstream, receives capability response
3. Daemon filters capabilities based on policies (removes denied tools/resources, removes sampling if disabled)
4. Filtered capabilities returned to client
5. Client's LLM never knows about tools/resources it can't use

### Key Design Decisions

- **Terminate/inspect/re-originate over byte-level proxying:** A security tool must fully own both sides of the connection. Forwarding raw bytes means trusting the wire. Full protocol termination means nothing reaches the upstream unless MCP-Guard constructed it.
- **Daemon + thin bridge over one-process-per-server:** Enables cross-server rate limits, centralized audit, unified identity management, hot config reload, and a real-time dashboard. The daemon is the single vantage point for security.
- **Auto-start over explicit daemon management:** The ssh-agent/gpg-agent pattern. The daemon materializes when first needed. Zero ceremony for solo devs, explicit `mcp-guard start` available for ops teams.
- **Structurally fail-closed bridge:** The bridge binary contains no upstream connection code. It literally cannot bypass the daemon because the code doesn't exist. This is a structural guarantee, not a behavioral one.
- **Audit tap as structural observer, not middleware:** The audit system is wired into the daemon's message handling, not the interceptor chain. It cannot be skipped by a misconfigured pipeline, a thrown error, or a timeout. It sees every message including blocked ones.
- **Floor-based config merge:** Personal configs can only restrict, never relax base policies. This is enforced structurally by the config merger — the merge function computes intersections for allowlists and unions for denylists.
- **Persistent rate limiting over in-memory:** Enterprise requirement. Rate limits survive daemon restarts, preventing bypass via restart. SQLite is already in use for audit logs, so zero additional operational overhead.
- **Sampling disabled by default:** MCP sampling/createMessage lets servers inject prompts into the user's LLM. This is a uniquely dangerous capability that must be explicitly opted into.

---

## Core Features

### Feature 1: Daemon Lifecycle & Bridge Protocol

**What it does:** Manages the long-running daemon process, Unix socket server, auto-start, graceful shutdown, and the thin bridge protocol.

**Auto-start flow:**
1. Bridge process starts, checks for daemon via Unix socket
2. If daemon not running: fork and detach a daemon process, wait for socket to become available (~100ms)
3. Bridge authenticates to daemon using daemon.key (generated on first run, stored at `~/.config/mcp-guard/daemon.key`)
4. Daemon verifies: key matches, peer credential verification (SO_PEERCRED on Linux, getpeereid()+LOCAL_PEERPID on macOS via koffi) UID matches daemon's UID, socket permissions are 0600
5. Authenticated channel established; bridge begins forwarding stdio

**Graceful shutdown:**
1. Daemon receives SIGTERM
2. Stop accepting new bridge connections
3. In-flight requests complete (configurable timeout, default 30s)
4. Bridges notified of shutdown via socket
5. Bridges exit with non-zero code (MCP client reports server unavailable)
6. Audit log flushed and synced
7. SQLite WAL checkpointed
8. Daemon exits

**Health endpoint:**
- `GET /healthz` returns 200 with JSON: daemon uptime, connected bridge count, upstream server statuses, SQLite status, last successful audit write
- `mcp-guard health` CLI: exit code 0 if healthy, 1 if not

### Feature 2: Interceptor Pipeline

**What it does:** Processes every MCP message through a fixed-order security pipeline with strict fail-closed semantics.

**Execution contract:**
- Request interceptors run in fixed order: Auth → RateLimit → Permissions → PII Detect
- Response interceptors: PII Detect (buffered)
- Each interceptor returns: PASS, MODIFY, or BLOCK
- If any interceptor throws: request BLOCKED (fail-closed)
- If any interceptor exceeds its timeout: request BLOCKED (fail-closed)
- Custom/plugin interceptors run after built-ins on request path
- Custom interceptors can only MODIFY params/content — mutations to tool names, methods, or resource URIs are rejected by the pipeline runner (structural constraint via post-interceptor diff)
- Audit tap observes everything — it runs outside the chain, cannot be skipped

**Per-interceptor timeout:**
```yaml
interceptors:
  pii:
    timeout: 5s
    timeout_action: block    # default
```

### Feature 3: Authentication & Identity

**What it does:** Identifies who is making each MCP request and maps identities to roles with specific permissions.

**OS identity mode (default):**
- Reads peer credential verification (SO_PEERCRED on Linux, getpeereid()+LOCAL_PEERPID on macOS via koffi) from Unix socket to get connecting process's OS user
- Maps OS username to roles defined in config
- Zero setup required

**Token auth mode (enterprise):**
- `mcp-guard auth login` opens browser for OAuth flow, stores token
- Bridge passes token to daemon on connect
- Daemon validates against configured provider (OAuth 2.1 introspection, JWT validation)
- Maps claims to roles

**Role-based permissions:**
```yaml
auth:
  mode: token
  provider:
    type: oauth2
    issuer: "https://auth.company.com"
    audience: "mcp-guard"
  roles:
    admin:
      claims: { "groups": ["security-team"] }
      permissions: { allow: ["*"] }
    developer:
      claims: { "groups": ["engineering"] }
      permissions:
        denied_tools: ["delete_*", "drop_*"]
      rate_limit:
        requests_per_minute: 60
```

### Feature 4: PII Detection

**What it does:** Scans MCP request parameters and response content for personally identifiable information using a pluggable detector system.

**Pluggable detector interface:**
```typescript
interface PIIDetector {
  name: string;
  detect(content: string, ctx: DetectionContext): Promise<PIIMatch[]>;
}
```

**Built-in regex detector covers:** email addresses, phone numbers (international), SSNs, credit card numbers (Luhn-validated), AWS access keys, GitHub tokens, generic high-entropy strings.

**Directional actions:**
```yaml
pii:
  actions:
    ssn:
      request: block     # never let SSNs flow to upstream servers
      response: warn     # flag but allow (user's own data)
    api_key:
      request: redact
      response: redact
```

**Custom PII types (enterprise):**
```yaml
pii:
  custom_types:
    mrn:
      label: "Medical Record Number"
      patterns:
        - regex: "MRN[:\\s]*\\d{8,10}"
      actions:
        request: block
        response: redact
```

**Streaming handling:** Response PII detection uses buffered mode by default — accumulates full response before scanning. Opt-in `streaming: true` mode uses a sliding window detector for latency-sensitive use cases.

**Structural guarantee:** Redacted values are never stored in the audit log. The log records that redaction occurred and the PII type, but the original value is gone.

### Feature 5: Configuration System

**What it does:** Declarative YAML config with type-safe validation, composable inheritance for teams, and hot reload.

**Composability via extends:**
```yaml
extends:
  url: "https://security.company.com/mcp-guard-base.yaml"
  sha256: "a1b2c3d4..."   # required — daemon refuses to start if hash doesn't match
```

**Floor-based merge semantics (structural enforcement):**
- `allowed_tools`: intersected with base (can only narrow)
- `denied_tools`: unioned with base (can only add denials)
- `rate_limit`: takes the stricter value (lower of the two)
- `pii.detectors`: can add detectors, cannot remove base detectors
- `locked: true` policies: cannot be overridden at all

**Extends fetch failure:** If the `extends` URL is unreachable at daemon startup, the daemon uses the last-known-good cached copy (stored locally alongside the hash). If no cache exists (first-ever startup), the daemon refuses to start (fail-closed). The cached copy is re-verified against its SHA-256 hash before use.

**Hot reload:** Daemon watches config file. Policy changes apply immediately. Server definition changes trigger graceful restart of affected connections.

### Feature 6: Audit Logging

**What it does:** Records every MCP interaction to a queryable database with optional encryption at rest, plus structured stdout logging for container deployments.

**Storage:**
- SQLite with WAL mode for concurrent reads/writes
- Optional SQLCipher encryption (key derived from daemon.key)
- 0600 file permissions
- Configurable retention (default 90 days)

**Each log entry contains:** timestamp, direction (request/response), server name, MCP message type, tool/resource name, parameters (with PII redacted), result status, latency, identity (user/role), all interceptor decisions, whether the request was blocked and by which interceptor.

**Dual output:**
- SQLite for CLI queries and dashboard
- Structured JSON on stdout for container log pipelines

**CLI query interface:**
```bash
mcp-guard logs                             # recent logs
mcp-guard logs --server github --last 1h   # filtered
mcp-guard logs --user jacob --type block   # blocked requests by user
mcp-guard logs --export csv > audit.csv    # export
```

### Feature 7: Sampling Guard

**What it does:** Controls whether MCP servers can use `sampling/createMessage` to request LLM completions from the client.

**Why this is critical:** A compromised MCP server with sampling access can inject arbitrary prompts into the user's LLM, exfiltrate data through crafted prompts, or chain attacks across servers.

**Default: disabled (fail-closed).** Servers must be explicitly granted sampling access:
```yaml
servers:
  trusted-server:
    policies:
      sampling:
        enabled: true
        max_tokens: 1000
        rate_limit: 5/minute
        audit: verbose    # log full prompt content
```

**Capability filtering:** If sampling is disabled for a server, the sampling capability is removed from the server's capability advertisement during initialize. The client's LLM never knows the server supports sampling.

---

## Security & Configuration

### Authentication

**Bridge → Daemon:** Per-installation daemon.key generated on first run. Stored at `~/.config/mcp-guard/daemon.key` with 0600 permissions. Bridge presents key on Unix socket connect. Daemon verifies key + peer credential verification (SO_PEERCRED on Linux, getpeereid()+LOCAL_PEERPID on macOS via koffi) UID match.

**Client → MCP-Guard:** OS identity (default) or OAuth 2.1 tokens (enterprise). Identity resolved at the daemon, never at the bridge.

**Dashboard:** Auth token generated on first run. Required by default. Displayed via `mcp-guard dashboard-token`.

### Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `MCP_GUARD_CONFIG` | Custom config file path | No (default: `./mcp-guard.yaml`) |
| `MCP_GUARD_HOME` | Config/data directory | No (default: `~/.config/mcp-guard/`) |
| `MCP_GUARD_LOG_LEVEL` | Daemon log level | No (default: `info`) |
| Any vars referenced in config `${...}` | Upstream server credentials | Depends on config |

### Deployment

**Solo developer:** `npm install -g mcp-guard`, edit client config, done. Daemon auto-starts.

**Team/Enterprise:** Security team publishes base config at a URL, developers `extends` it with SHA-256 pin. Token auth via corporate OAuth provider. Monitoring via /healthz endpoint.

**Container:** Docker image with config mounted as volume. Structured JSON logs on stdout for log aggregation. Health endpoint for liveness probes.

---

## Implementation Phases

### Phase 1: Foundation
**Goal:** Daemon lifecycle, bridge protocol, basic proxy, config system
- [ ] Project scaffolding (package.json, tsconfig, vitest, eslint, CI)
- [ ] Config schema (Zod) and YAML loader (without extends — local file only)
- [ ] Daemon process: start, stop, Unix socket server, auto-start
- [ ] Daemon key generation and bridge authentication
- [ ] Bridge process: stdio-to-socket forwarding with auth
- [ ] Basic MCP proxy: Server instance (client-facing) + Client instance (upstream-facing) for stdio transport
- [ ] Message passthrough (no interceptors yet — just proxy all messages)
- [ ] Graceful shutdown

**Validation:** `mcp-guard connect --server X` proxies an MCP server transparently; all tool calls work; daemon auto-starts on first connect; graceful shutdown works.

### Phase 2: Interceptor Pipeline + Auth
**Goal:** The security core — interceptor pipeline with auth and rate limiting
- [ ] Interceptor pipeline runner with timeout and fail-closed semantics
- [ ] Audit tap (structural observer) + SQLite storage with WAL
- [ ] Auth interceptor: OS identity via peer credential verification (SO_PEERCRED on Linux, getpeereid()+LOCAL_PEERPID on macOS via koffi)
- [ ] Auth interceptor: API key validation
- [ ] Rate limit interceptor: token bucket with SQLite persistence
- [ ] Permission interceptor: tool/resource allow/deny lists
- [ ] Capability filtering on initialize response
- [ ] CLI: `mcp-guard logs` query interface

**Validation:** Unauthorized requests blocked; rate limits enforced and survive restart; denied tools filtered from capability list; all interactions logged to SQLite; `mcp-guard logs` returns results.

### Phase 3: PII Detection + Sampling Guard
**Goal:** Content-level security — PII scanning and sampling control
- [ ] PIIDetector interface and registry
- [ ] Built-in regex detector (emails, phones, SSNs, credit cards, API keys)
- [ ] Directional PII actions (request vs response)
- [ ] Custom PII types in config
- [ ] Buffered response scanning
- [ ] Redaction (structural — original never stored)
- [ ] Sampling guard interceptor (disabled by default)
- [ ] Capability filtering for sampling

**Validation:** PII detected in requests and responses; redaction works; redacted values never appear in audit log; sampling blocked by default; sampling enabled servers work with rate limits.

### Phase 4: Enterprise Features
**Goal:** Multi-user identity, config composability, dashboard
- [ ] OAuth 2.1 token auth with `mcp-guard auth login/status/logout`
- [ ] Role-based permission mapping from OAuth claims
- [ ] Config `extends` with SHA-256 pinning
- [ ] Floor-based merge semantics
- [ ] `locked: true` policy enforcement
- [ ] Hot config reload
- [ ] Dashboard: HTTP server with token auth
- [ ] Dashboard: real-time proxy status, request timeline, PII alerts
- [ ] Health endpoint (/healthz)
- [ ] Structured JSON stdout logging
- [ ] SQLCipher encryption at rest (optional)
- [ ] SSE transport support for upstream servers

**Validation:** Multiple users with different roles get different permissions; base config restrictions cannot be relaxed by personal configs; dashboard shows live traffic; health endpoint works; encrypted database works.

### Phase 5: Benchmarks + Launch
**Goal:** Benchmark suite, documentation, public launch
- [ ] Tier 1 mock MCP servers (8-10 archetypes)
- [ ] Security benchmark scenarios (10 categories, 450+ each)
- [ ] Legitimate traffic baseline (10,000+ benign requests for false positive measurement)
- [ ] Performance benchmarks (latency overhead, concurrency, throughput)
- [ ] Tier 2 compatibility tests (open-source servers via Docker Compose)
- [ ] Chart and table generation (SVG + markdown)
- [ ] README with benchmark results, architecture diagram, quick start
- [ ] CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, CHANGELOG.md
- [ ] Docker image and docker-compose
- [ ] npm publish setup
- [ ] Blog post: methodology, findings, results
- [ ] `mcp-guard init` command (generate config from existing client configs)
- [ ] `mcp-guard validate` and `mcp-guard status` commands

**Validation:** `pnpm benchmark` runs Tier 1+2 and produces charts; detection rate >95%; false positive rate <0.1%; p50 latency overhead <5ms; 20/20 server compatibility; npm install and Docker run both work; README is complete.

---

## Success Criteria

- [ ] Transparently proxies all MCP message types across stdio and SSE transports
- [ ] Daemon auto-starts on first bridge connection with zero ceremony
- [ ] Bridge is structurally fail-closed (no upstream code in binary)
- [ ] Bridge-to-daemon channel authenticated (daemon.key + peer credential verification (SO_PEERCRED on Linux, getpeereid()+LOCAL_PEERPID on macOS via koffi))
- [ ] OAuth 2.1 and API key authentication working with role-based permissions
- [ ] Rate limiting enforced per client/server/tool, persistent across restarts
- [ ] Permission scoping enforced; denied tools/resources filtered from capabilities
- [ ] Sampling/createMessage blocked by default, configurable per server
- [ ] PII detection with directional redact/warn/block actions, custom PII types
- [ ] Redacted PII values never stored in audit log
- [ ] All MCP interactions logged to queryable SQLite audit trail with optional encryption
- [ ] Structured JSON logs on stdout for container deployments
- [ ] Config composability via extends with SHA-256 pinning and floor-based merge
- [ ] Dashboard with token auth showing real-time proxy status
- [ ] Graceful shutdown with in-flight completion and audit flush
- [ ] Health endpoint for monitoring systems
- [ ] >95% detection rate across 4,500+ attack simulations
- [ ] <0.1% false positive rate across 10,000+ legitimate requests
- [ ] <5ms p50 latency overhead across 10,000 requests
- [ ] 20/20 popular MCP servers compatible
- [ ] Published to npm: `npx mcp-guard start`
- [ ] Docker image available at ghcr.io
- [ ] Blog post with honest benchmark methodology published

---

## Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|------------|
| MCP SDK API changes break proxy | High | Medium | Pin SDK version, abstract behind internal interfaces, test against multiple SDK versions in CI |
| Latency overhead exceeds 5ms target | Medium | Medium | Profile early in Phase 1, benchmark continuously, optimize hot path (interceptor pipeline) |
| False positive rate too high for real-world use | High | Medium | Tune regex patterns against large corpus of legitimate MCP traffic, per-PII-type confidence thresholds |
| SQLite contention under high concurrency | Medium | Low | WAL mode handles concurrent readers well; write batching for audit logs if needed |
| Auto-start race condition (multiple bridges starting daemon simultaneously) | Medium | Medium | File lock on daemon.pid, second bridge waits for socket availability |
| MCP clients behave differently with capability filtering | High | Low | Extensive compatibility testing; filter conservatively; option to disable filtering |
| Enterprise config extends URL becomes single point of failure | Medium | Low | Daemon caches last-known-good base config locally; uses cache if fetch fails |
| Bridge authentication bypassed via daemon.key theft | High | Low | 0600 permissions, peer credential verification (SO_PEERCRED on Linux, getpeereid()+LOCAL_PEERPID on macOS via koffi) verification, rotate key via `mcp-guard rotate-key` |

---

## Assumptions (Validated)

1. **MCP SDK composition: VALIDATED.** The SDK has no singletons or global state. Multiple Server and Client instances can coexist in one process. Each has a 1:1 relationship with its transport, which aligns with our architecture (one Server per bridge, one Client per upstream). This is the recommended pattern for multi-user scenarios per SDK GitHub issues #204 and #243.
2. **Unix socket availability:** The daemon uses Unix domain sockets, available on macOS and Linux. Windows support would require named pipes — deferred to post-MVP.
3. **Peer credential verification: VALIDATED.** Linux uses SO_PEERCRED via getsockopt(). macOS uses getpeereid() for UID/GID and LOCAL_PEERPID for PID. Both are accessible from Node.js via the `koffi` FFI package (pure N-API, no compilation required). Tested and confirmed working on macOS Darwin 25.4.0.
4. **SQLCipher distribution: VALIDATED.** `better-sqlite3-multiple-ciphers` is a drop-in replacement for `better-sqlite3` with built-in encryption support. Prebuilt binaries available for macOS (x64/arm64), Linux (x64/arm64), Windows (x64/arm64), and Alpine Linux. npm install takes ~1.7s with zero compilation. API is identical — just add `db.pragma("key='...'")` after opening.
5. **MCP client process model:** We assume MCP clients (Cursor, Claude Desktop, etc.) spawn server processes independently and don't share state between them. The thin bridge model relies on this.
