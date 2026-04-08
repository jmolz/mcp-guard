# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

MCP-Guard is a security proxy daemon for the MCP (Model Context Protocol) ecosystem. It sits between MCP clients (Cursor, Claude Desktop, Claude Code, VS Code) and MCP servers, adding OAuth 2.1 authentication, rate limiting, PII detection, permission scoping, and audit logging to any MCP server — without modifying it. It operates on a **terminate, inspect, re-originate** architecture: MCP-Guard fully terminates the client connection, applies a security interceptor pipeline, then re-originates the request to the upstream server. Nothing passes through uninspected.

- **Repository**: https://github.com/jmolz/mcp-guard
- **SSH**: `git@github.com:jmolz/mcp-guard.git`

---

## Tech Stack

| Technology | Purpose |
|------------|---------|
| TypeScript (Node 22+) | Core language and runtime |
| @modelcontextprotocol/sdk | MCP Server + Client protocol instances |
| Commander.js | CLI framework |
| js-yaml + zod | YAML config parsing + schema validation |
| jose + oauth4webapi | JWT validation and OAuth 2.1 |
| better-sqlite3-multiple-ciphers | Audit logs, rate limits, sessions (SQLCipher support) |
| koffi | Unix socket peer credential verification (FFI) |
| htmx | Dashboard web UI |
| tsup | Build and bundling |
| vitest | Testing |
| pnpm | Package manager |

---

## Commands

```bash
# Development
pnpm dev                  # Start daemon in dev mode (tsx watch)

# Build
pnpm build                # Production build (tsup)

# Test
pnpm test                 # Run test suite (vitest)
pnpm test:watch           # Watch mode
pnpm test -- --coverage   # With coverage

# Lint & Format
pnpm lint                 # ESLint check
pnpm lint:fix             # ESLint auto-fix
pnpm format               # Prettier format
pnpm typecheck            # tsc --noEmit

# Benchmarks
pnpm benchmark            # Full benchmark suite (~5-10 min)
pnpm benchmark:quick      # Stratified sample (~30s)
pnpm benchmark:security   # Security scenarios only
pnpm benchmark:legitimate # False positive measurement only
pnpm benchmark:performance # Latency + concurrency only

# Full Validation (run before every commit)
pnpm lint && pnpm typecheck && pnpm test && pnpm build
```

---

## Project Structure

```
mcp-guard/
├── src/
│   ├── daemon/                  # Daemon process (long-running)
│   │   ├── index.ts             # Daemon entry point and lifecycle
│   │   ├── server-manager.ts    # Manages upstream MCP server connections
│   │   ├── socket-server.ts     # Unix socket server for bridge connections
│   │   ├── auto-start.ts        # Auto-start logic (fork + detach)
│   │   └── shutdown.ts          # Graceful shutdown handler
│   ├── bridge/                  # Thin bridge process (~50 lines, zero policy logic)
│   │   ├── index.ts             # Bridge entry point
│   │   └── auth.ts              # Daemon authentication
│   ├── proxy/                   # MCP protocol handling
│   │   ├── mcp-server.ts        # MCP Server instance (faces client)
│   │   ├── mcp-client.ts        # MCP Client instance (faces upstream)
│   │   ├── capability-filter.ts # Filters capabilities based on policies
│   │   └── message-router.ts    # Routes messages through interceptor pipeline
│   ├── interceptors/            # Security interceptor pipeline
│   │   ├── pipeline.ts          # Pipeline runner with timeout + fail-closed + identity propagation
│   │   ├── types.ts             # Interceptor interface, Decision type, ResolvedIdentity
│   │   ├── auth.ts              # Authentication interceptor (OS, API key, OAuth)
│   │   ├── rate-limit.ts        # Rate limiting interceptor (with role-based effective limits)
│   │   ├── permissions.ts       # Permission scoping interceptor (with role-based effective perms)
│   │   ├── effective-policy.ts  # Floor-based merge of server + role policies
│   │   ├── pii-detect.ts        # PII detection interceptor
│   │   └── sampling-guard.ts    # Sampling/createMessage policy
│   ├── pii/                     # PII detection system
│   │   ├── types.ts             # PIIDetector interface, PIIMatch, PIIMatchSafe, PIIAction
│   │   ├── regex-detector.ts    # Built-in regex detector (email, phone, SSN, CC+Luhn, AWS, GitHub)
│   │   ├── registry.ts          # Detector registry (built-in + custom, confidence filtering)
│   │   └── redactor.ts          # Span-based redaction, structured object scanning
│   ├── audit/                   # Audit logging
│   │   ├── tap.ts               # Structural audit tap (observer, not middleware)
│   │   ├── store.ts             # SQLite audit storage
│   │   ├── query.ts             # Audit log query engine
│   │   └── stdout-logger.ts     # Structured JSON stdout logger
│   ├── identity/                # Identity and auth
│   │   ├── os-identity.ts       # Peer credential verification (koffi FFI)
│   │   ├── token-validator.ts   # JWT validation via jose (JWKS, OIDC discovery)
│   │   ├── token-store.ts       # OAuth token filesystem storage (0600 perms)
│   │   ├── oauth-flow.ts        # OAuth 2.1 Authorization Code + PKCE flow
│   │   ├── roles.ts             # Role resolution (OS + OAuth claims-to-role mapping)
│   │   └── daemon-key.ts        # Daemon key generation and verification
│   ├── config/                  # Configuration system
│   │   ├── schema.ts            # Zod schema definitions (extends, locked, encryption)
│   │   ├── loader.ts            # YAML loading with extends resolution + reloadConfig
│   │   ├── fetcher.ts           # HTTP fetch + SHA-256 verification + local cache
│   │   ├── merger.ts            # Floor-based merge semantics (security-critical)
│   │   └── watcher.ts           # Hot reload file watcher (fs.watch + debounce)
│   ├── storage/                 # Database layer
│   │   ├── sqlite.ts            # SQLite connection with WAL + optional SQLCipher
│   │   ├── migrations.ts        # Schema migrations
│   │   └── rate-limit-store.ts  # RateLimitStore interface + SQLite impl
│   ├── dashboard/               # Web dashboard
│   │   ├── server.ts            # HTTP server with Bearer token auth (/healthz, /api/status)
│   │   ├── health.ts            # Health endpoint handler (healthy/degraded/unhealthy)
│   │   └── views/               # HTML + htmx templates (Phase 4C)
│   ├── cli/                     # CLI subcommands
│   │   └── init.ts              # mcp-guard init (config discovery, ${VAR} placeholders)
│   └── cli.ts                   # CLI entry point (Commander.js)
├── tests/                       # Test files (mirrors src/ structure)
│   └── compat/                  # Tier 2 compatibility tests (env-gated)
├── benchmarks/                  # Security + performance benchmarks
│   ├── mock-servers/            # 8 MCP server archetypes (filesystem, database, etc.)
│   ├── security/                # 10 attack category generators (4,500+ scenarios)
│   │   ├── generator.ts         # Registry, builder helpers, stratifiedSample
│   │   ├── categories/          # permission-bypass, pii-evasion, rate-limit, etc.
│   │   └── run-security.ts      # Security runner + audit integrity check
│   ├── legitimate/              # 10,000+ benign requests (false positive measurement)
│   ├── performance/             # Latency (p50/p95/p99), concurrency, throughput
│   ├── report/                  # SVG chart + markdown table generation
│   ├── configs/                 # Benchmark-specific YAML configs
│   ├── runner.ts                # Orchestrator (exits non-zero on threshold breach)
│   └── types.ts                 # BenchmarkScenario, BurstGroup, result types
├── docker/                      # Dockerfile, docker-compose
├── .github/workflows/           # CI, release, security scanning
└── docs/                        # User-facing documentation
```

---

## Architecture

### Three Process Types

1. **Daemon** (`mcp-guard start`) — Long-running. Manages all upstream MCP server connections, runs the interceptor pipeline, owns the SQLite database, serves the dashboard. Auto-starts on first bridge connection.
2. **Bridge** (`mcp-guard connect --server <name>`) — Thin stdio relay. Contains **zero policy logic and zero upstream connection code**. Structurally fail-closed.
3. **CLI** (`mcp-guard logs`, `status`, etc.) — Stateless commands. Talks to daemon or reads SQLite directly.

### Data Flow

```
Client → Bridge (stdio) → Daemon (Unix socket) → Interceptor Pipeline → Upstream MCP Server
                                                       │
                                                  Audit Tap (structural observer)
```

**Request path:** Auth → RateLimit → Permissions → SamplingGuard → PII Detect → [upstream] → PII Detect → [client]

### Key Architectural Invariants

- **Terminate/inspect/re-originate**: The daemon fully owns both connections. No byte-level proxying.
- **Audit tap is structural**: Wired into the daemon's message handling, not the interceptor chain. Cannot be skipped by misconfigured pipelines, errors, or timeouts.
- **Floor-based config merge**: Personal configs can only restrict, never relax base policies. `allowed_tools` intersected, `denied_tools` unioned, `rate_limit` takes stricter value.
- **Sampling disabled by default**: Fail-closed. Must be explicitly enabled per server.

---

## Code Patterns

### Naming

- Files: `kebab-case.ts` (e.g., `rate-limit-store.ts`, `mcp-server.ts`)
- Functions/methods: `camelCase`
- Types/Interfaces: `PascalCase` (e.g., `PIIDetector`, `InterceptorDecision`)
- Constants: `UPPER_SNAKE_CASE` for true constants, `camelCase` for derived values
- Enums: `PascalCase` names, `PascalCase` members

### Imports

- Relative imports within a module (e.g., `./types`)
- Path-mapped imports across modules (e.g., `@/interceptors/types`)
- Named imports only, no namespace imports
- Node built-ins with `node:` prefix (e.g., `import { readFile } from 'node:fs/promises'`)

### Error Handling

- **Fail-closed by default**: Any unhandled error in the interceptor pipeline blocks the request
- Use typed error classes extending `McpGuardError` base class
- Error classes: `ConfigError`, `AuthError`, `PipelineError`, `StorageError`, `BridgeError`, `DashboardError`, `OAuthError`
- Never swallow errors silently — log at minimum, block if in security path
- External boundaries (config loading, upstream connections, socket I/O) use try/catch with typed errors
- Internal module boundaries trust their inputs (validated at the boundary)

### Logging

- Structured logging via a lightweight internal logger (not a framework)
- Levels: `debug`, `info`, `warn`, `error`
- Format: JSON objects to stdout (daemon), human-readable to stderr (CLI)
- Always include `{ component, server?, bridge? }` context
- Audit logging is separate from application logging — audit goes to SQLite + structured stdout

---

## Testing

- **Framework**: vitest
- **Location**: `tests/` directory, mirroring `src/` structure (e.g., `tests/interceptors/pipeline.test.ts`)
- **Run**: `pnpm test`
- **Minimum coverage**: Each module needs happy path + edge case + error/failure case
- **Patterns**:
  - Unit tests for pure logic (interceptors, PII detectors, config merger, redactor)
  - Integration tests for daemon/bridge communication (spawn real processes)
  - Use vitest's built-in mocking — `vi.mock()` for module mocks, `vi.fn()` for function mocks
  - Test fixtures in `tests/fixtures/` (sample configs, mock MCP messages)
  - Security-critical code (interceptor pipeline, PII redaction, auth) requires negative tests proving the fail-closed path works

---

## Validation (Pre-Commit)

Run these before every commit:

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

---

## On-Demand Context

When working on specific areas, read the corresponding reference:

| Area | File | When |
|------|------|------|
| Interceptor pipeline | `.claude/rules/interceptors.md` | Adding/modifying interceptors |
| Daemon lifecycle | `.claude/rules/daemon.md` | Daemon, bridge, socket, shutdown |
| Security patterns | `.claude/rules/security.md` | Auth, crypto, permissions, fail-closed |
| Config system | `.claude/rules/config.md` | Schema, loader, merger, validation |
| Testing strategy | `.claude/rules/testing.md` | Writing tests for any module |
| Benchmarks | `.claude/rules/benchmarks.md` | Adding scenarios, mock servers, running benchmarks |
| CI/CD workflows | `.claude/rules/ci.md` | GitHub Actions, package.json CI fields, cross-platform |
| Publishing & releases | `.claude/rules/publishing.md` | npm/Docker publish, release prerequisites, pre-publish checklist |
| Full PRD | `.claude/PRD.md` | Feature specs, implementation phases |
| Architecture deep-dive | `.claude/docs/architecture.md` | System design reference |

---

## Key Rules

### Security (this is a security tool — these are non-negotiable)

- **Fail-closed everywhere**: If in doubt, block. Interceptor throws? Block. Timeout? Block. Auth fails? Block.
- **Never store raw PII in audit logs**: Log that redaction occurred and the PII type, never the original value.
- **Bridge must stay thin**: The bridge process must contain zero policy logic and zero upstream connection code. This is a structural guarantee.
- **Daemon key is 0600**: Daemon key (at `{daemon.home}/daemon.key`) and Unix socket must have 0600 permissions. Verify on startup. Both `ensureDaemonKey` and `readDaemonKey` enforce this — only `ENOENT` is suppressed during key check, all other FS errors are fatal.
- **Sampling disabled by default**: `sampling/createMessage` must be explicitly enabled per server. Capability removed from advertisement if disabled.
- **Parameterized SQL only**: All SQLite queries use parameterized statements. No string interpolation in SQL, ever.
- **Init never writes client configs**: `mcp-guard init` only reads client config files. Discovered env vars are emitted as `${VAR}` placeholders, never raw secret values.
- **No `any` types in security paths**: Interceptors, auth, PII detection, and audit code must be fully typed.

### Architecture

- **Interceptor order is fixed**: Auth → RateLimit → Permissions → SamplingGuard → PII Detect. This order is not configurable. A separate response pipeline runs PII Detect only on upstream responses (including error payloads).
- **Audit tap is not an interceptor**: It observes all messages (including blocked ones) from outside the chain.
- **Three decisions only**: Interceptors return `PASS`, `MODIFY`, or `BLOCK`. No other outcomes.
- **Custom interceptors are sandboxed**: They can only modify `params`/`content`. Mutations to tool names, methods, or resource URIs are rejected by the pipeline runner.
- **Config merge is floor-based**: Personal configs can restrict but never relax base policies. This is enforced by the merger, not by convention.

### Evaluation & Review Process

- **Never skip adversarial review steps**: When a plan contract specifies Codex adversarial review (Tier 2+), it MUST be attempted. If the tooling fails or is not configured, report the error to the user — do not silently skip it or decide on your own that it's unavailable.
- **Never unilaterally skip or downgrade any evaluation step**: All steps specified in a plan contract (Tier levels, Codex review, Claude evaluator passes) are mandatory. If any step cannot be completed for technical reasons, report the blocker and ask the user how to proceed.
- **Evaluation decisions belong to the user**: The agent does not have authority to decide that a review step is unnecessary, that a threshold can be lowered, or that a failing criterion can be accepted. Present findings and let the user decide.

### Code Quality

- **No `any` without justification**: If truly unavoidable, add `// SAFETY: <reason>` comment.
- **Zod schemas are the source of truth**: Config types are inferred from Zod schemas (`z.infer<typeof schema>`), not hand-written.
- **Node built-ins use `node:` prefix**: `import { readFile } from 'node:fs/promises'`, not `'fs/promises'`.
- **No default exports**: Use named exports everywhere for grep-ability.
- **Errors are typed**: Use the project's error class hierarchy, not bare `Error`.

### Implementation Phases

The PRD defines 5 phases. **All phases complete (1 through 5B).** The project includes: daemon, bridge, proxy, config (extends + floor-based merge + hot reload), CLI (including `mcp-guard init`), interceptor pipeline (auth, rate-limit, permissions, sampling-guard, pii-detect), PII detection with Luhn validation, bidirectional response scanning, sampling guard, capability filtering, audit system with PII metadata, dashboard HTTP server with health endpoint, SQLCipher encryption at rest, OAuth 2.1 JWT auth with claims-to-role mapping, SSE + Streamable HTTP transport, role-based effective policy resolution, benchmark infrastructure (8 mock servers, 10 security categories with 4,500+ attack scenarios, 10K+ legitimate traffic, performance harness), SVG chart + markdown report generation, Docker packaging, CI/CD workflows (release, benchmarks, security scanning), and full documentation suite. 362 tests across 38 test files (+15 env-gated Tier 2 compat tests).
