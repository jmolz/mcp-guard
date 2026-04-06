# Product Requirements Document: MCP-Guard

## Overview

MCP-Guard is a lightweight security proxy that sits between MCP clients (Cursor, Claude Desktop, Claude Code, VS Code, etc.) and MCP servers, adding OAuth 2.1 authentication, rate limiting, request/response logging, PII detection, and permission scoping to *any* MCP server — without modifying it.

Think of it as nginx for MCP. You configure security policies declaratively in YAML, point your MCP client at MCP-Guard instead of the raw server, and MCP-Guard enforces your policies transparently.

## Why this exists

MCP security is critically broken:
- Only 8.5% of MCP servers implement OAuth (Astrix Security audit)
- ~1,000 MCP servers are exposed on the public internet with zero authentication (Bitsight research)
- 88% of MCP servers need credentials but 53% use insecure static secrets
- Multiple CVEs disclosed: CVE-2025-6514 (mcp-remote, 437K+ downloads), CVE-2025-53109 (symlink bypass), redirect URI attacks, confused deputy attacks
- OWASP created an entire MCP Top 10 risk catalog
- The MCP 2026 roadmap lists gateway/proxy patterns and authorization propagation as open problems
- 24.9% of enterprises with 2K+ employees cite security as their top agent concern (LangChain survey)

Nobody has built a drop-in security proxy for the MCP ecosystem. MCP-Guard fills this gap.

## Target users

1. **Engineers using MCP servers with AI coding tools** — want to add auth and logging without modifying every server
2. **Teams deploying MCP servers in production** — need security compliance, audit trails, rate limiting
3. **Enterprise security teams** — need to approve MCP server usage, require PII detection and access controls
4. **MCP server developers** — want to test their servers' security posture

## Non-goals

- Replacing the MCP protocol or specification
- Building a full identity provider (we integrate with existing OAuth providers)
- Modifying MCP server code (we're a transparent proxy)
- Building an MCP client (we proxy between existing clients and servers)

---

## Repo infrastructure

Everything that makes this look and feel like a production-grade open-source project from day one.

### GitHub repo settings

**Description:**
```
Security proxy for MCP servers. Adds OAuth 2.1, rate limiting, PII detection, and audit logging to any MCP server — without modifying it.
```

**Topics/Tags:**
```
mcp, model-context-protocol, security, proxy, oauth, rate-limiting,
pii-detection, audit-logging, ai-security, llm-security, mcp-server,
agent-security, ai-infrastructure
```

**Website:** Link to docs site or blog post once published

**Social preview image:** Custom OG image with MCP-Guard logo, tagline, and architecture diagram (1280×640px)

### License

MIT — `LICENSE` file in repo root. Same as PICE framework.

### File structure (repo root)

```
mcp-guard/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                    # Lint, typecheck, test on every push/PR
│   │   ├── release.yml               # Build + publish on tag push
│   │   ├── benchmarks.yml            # Run benchmarks on demand (workflow_dispatch)
│   │   └── security.yml              # CodeQL + dependency scanning weekly
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml            # Structured bug report form
│   │   ├── feature_request.yml       # Structured feature request form
│   │   └── security_vulnerability.yml # Responsible disclosure template
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── FUNDING.yml                   # GitHub Sponsors (optional, set up later)
│   ├── dependabot.yml                # Automated dependency updates
│   └── CODEOWNERS                    # @jmolz for all files
├── src/
├── benchmarks/
├── docs/
├── docker/
│   ├── Dockerfile                    # Production image
│   ├── Dockerfile.dev                # Dev image with hot reload
│   └── docker-compose.yml            # MCP-Guard + example MCP servers
├── .gitignore
├── .prettierrc
├── .eslintrc.js (or eslint.config.js)
├── tsconfig.json
├── vitest.config.ts
├── package.json
├── pnpm-lock.yaml
├── CLAUDE.md                         # Project rules for AI-assisted development
├── CHANGELOG.md                      # Keep a Changelog format
├── CODE_OF_CONDUCT.md                # Contributor Covenant
├── CONTRIBUTING.md                   # Dev setup, coding standards, PR process
├── SECURITY.md                       # Security policy + responsible disclosure
├── LICENSE                           # MIT
└── README.md
```

### CI pipeline (`.github/workflows/ci.yml`)

Runs on every push and pull request to `main`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: pnpm lint
      - run: pnpm typecheck

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: pnpm test -- --reporter=verbose
      - run: pnpm test -- --coverage
      - uses: actions/upload-artifact@v4
        with:
          name: coverage
          path: coverage/

  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: pnpm build

  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t mcp-guard:test -f docker/Dockerfile .
      - run: docker run --rm mcp-guard:test --version
```

### Release pipeline (`.github/workflows/release.yml`)

Triggered by pushing a version tag (`v*`):

```yaml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  publish-npm:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
          registry-url: 'https://registry.npmjs.org'
      - run: pnpm install --frozen-lockfile
      - run: pnpm build
      - run: pnpm test
      - run: pnpm publish --access public --no-git-checks
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

  publish-docker:
    runs-on: ubuntu-latest
    permissions:
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: docker/Dockerfile
          push: true
          tags: |
            ghcr.io/jmolz/mcp-guard:${{ github.ref_name }}
            ghcr.io/jmolz/mcp-guard:latest

  github-release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
```

### Security scanning (`.github/workflows/security.yml`)

```yaml
name: Security

on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am UTC
  workflow_dispatch:

jobs:
  codeql:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: javascript-typescript
      - uses: github/codeql-action/analyze@v3

  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4
```

### Dependabot (`.github/dependabot.yml`)

```yaml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    open-pull-requests-limit: 10
    groups:
      dev-dependencies:
        dependency-type: development
      production-dependencies:
        dependency-type: production

  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

### Issue templates

**Bug report (`.github/ISSUE_TEMPLATE/bug_report.yml`):**
```yaml
name: Bug Report
description: Report a bug in MCP-Guard
labels: [bug]
body:
  - type: textarea
    id: description
    attributes:
      label: What happened?
      placeholder: Describe the bug
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: What did you expect?
  - type: textarea
    id: reproduce
    attributes:
      label: Steps to reproduce
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: MCP-Guard version
      placeholder: "0.1.0"
    validations:
      required: true
  - type: dropdown
    id: transport
    attributes:
      label: MCP transport type
      options:
        - stdio
        - SSE
        - Both
  - type: textarea
    id: config
    attributes:
      label: MCP-Guard config (redact secrets)
      render: yaml
  - type: textarea
    id: logs
    attributes:
      label: Relevant log output
      render: shell
```

**Feature request (`.github/ISSUE_TEMPLATE/feature_request.yml`):**
```yaml
name: Feature Request
description: Suggest a feature for MCP-Guard
labels: [enhancement]
body:
  - type: textarea
    id: problem
    attributes:
      label: What problem does this solve?
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: Proposed solution
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
```

### PR template (`.github/PULL_REQUEST_TEMPLATE.md`)

```markdown
## What does this PR do?

<!-- Brief description -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security fix

## Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] `pnpm lint` passes
- [ ] `pnpm typecheck` passes
- [ ] `pnpm test` passes
- [ ] CHANGELOG.md updated (for user-facing changes)

## How to test

<!-- Steps for reviewers to verify -->
```

### SECURITY.md

```markdown
# Security Policy

## Reporting a Vulnerability

MCP-Guard takes security seriously — it's literally what the tool is for.

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Email: security@[your-domain].com
3. Or use GitHub's private vulnerability reporting:
   [Report a vulnerability](https://github.com/jmolz/mcp-guard/security/advisories/new)

We will acknowledge receipt within 48 hours and provide a timeline
for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | ✅        |

## Scope

The following are in scope for security reports:
- Authentication bypass in the proxy
- PII detection bypass
- Rate limiting bypass
- Audit log tampering or evasion
- Privilege escalation through MCP-Guard
- Vulnerabilities in dependencies
```

### CONTRIBUTING.md

```markdown
# Contributing to MCP-Guard

## Development setup

git clone https://github.com/jmolz/mcp-guard.git
cd mcp-guard
pnpm install
pnpm build
pnpm test

## Running locally

pnpm dev   # Starts with hot reload

## Code standards

- TypeScript strict mode
- All functions must have explicit return types
- All public APIs must have JSDoc comments
- Tests required for all new features (vitest)
- Lint: `pnpm lint`
- Format: `pnpm format`
- Typecheck: `pnpm typecheck`

## Commit convention

We use conventional commits:

feat: add OAuth 2.1 token introspection
fix: handle SSE reconnection on network failure
docs: add configuration examples for GitHub MCP
test: add rate limit bypass scenarios
perf: reduce proxy latency overhead by 2ms
security: patch token validation edge case

## PR process

1. Fork the repo
2. Create a feature branch from `main`
3. Make your changes with tests
4. Run `pnpm lint && pnpm typecheck && pnpm test`
5. Open a PR against `main`
6. Fill out the PR template

## Adding new interceptors

See `docs/interceptors.md` for the interceptor API.
Custom interceptors implement the `Interceptor` interface:

interface Interceptor {
  name: string;
  onRequest?(ctx: RequestContext): Promise<RequestDecision>;
  onResponse?(ctx: ResponseContext): Promise<ResponseDecision>;
}
```

### CHANGELOG.md

```markdown
# Changelog

All notable changes to MCP-Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-XX-XX

### Added
- Transparent proxy for MCP stdio and SSE transports
- OAuth 2.1 token validation
- API key authentication
- Token bucket rate limiting (per client, server, tool)
- SQLite audit logging with CLI query interface
- PII detection with configurable redact/warn/block actions
- Tool-level permission scoping (allow/deny lists)
- YAML-based declarative configuration
- Docker image and npm distribution
- Benchmark suite: 4,500+ security scenarios, 10K performance tests
- Compatibility testing across 20 MCP servers
```

### package.json essentials

```json
{
  "name": "mcp-guard",
  "version": "0.1.0",
  "description": "Security proxy for MCP servers. Adds OAuth 2.1, rate limiting, PII detection, and audit logging without modifying servers.",
  "license": "MIT",
  "author": "Jacob Molz <your-email>",
  "repository": {
    "type": "git",
    "url": "https://github.com/jmolz/mcp-guard"
  },
  "homepage": "https://github.com/jmolz/mcp-guard#readme",
  "bugs": {
    "url": "https://github.com/jmolz/mcp-guard/issues"
  },
  "keywords": [
    "mcp",
    "model-context-protocol",
    "security",
    "proxy",
    "oauth",
    "rate-limiting",
    "pii",
    "audit",
    "ai-security",
    "llm"
  ],
  "bin": {
    "mcp-guard": "./dist/cli.js"
  },
  "files": [
    "dist",
    "README.md",
    "LICENSE",
    "CHANGELOG.md"
  ],
  "engines": {
    "node": ">=20"
  },
  "scripts": {
    "build": "tsup",
    "dev": "tsup --watch",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:coverage": "vitest run --coverage",
    "lint": "eslint src/",
    "typecheck": "tsc --noEmit",
    "format": "prettier --write .",
    "format:check": "prettier --check .",
    "prepublishOnly": "pnpm build && pnpm test"
  }
}
```

### Docker distribution

**Dockerfile:**
```dockerfile
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM node:22-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
ENTRYPOINT ["node", "dist/cli.js"]
CMD ["start"]
```

**Usage:**
```bash
# Run from Docker
docker run -v ./mcp-guard.yaml:/app/mcp-guard.yaml ghcr.io/jmolz/mcp-guard:latest

# Or docker-compose with example servers
docker compose -f docker/docker-compose.yml up
```

### README badges (top of README)

```markdown
[![CI](https://github.com/jmolz/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/jmolz/mcp-guard/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/mcp-guard)](https://www.npmjs.com/package/mcp-guard)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fjmolz%2Fmcp--guard-blue)](https://ghcr.io/jmolz/mcp-guard)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]()
[![Detection Rate](https://img.shields.io/badge/detection_rate-99.X%25-brightgreen)]()
```

### GitHub Discussions

Enable Discussions on the repo with these categories:
- **Announcements** — release notes, roadmap updates
- **Q&A** — usage questions
- **Ideas** — feature suggestions from community
- **Show and Tell** — users sharing their MCP-Guard configs and setups

---

## Architecture

```
┌──────────────┐     ┌──────────────────────────────────┐     ┌──────────────┐
│  MCP Client  │     │           MCP-Guard               │     │  MCP Server  │
│  (Cursor,    │────▶│                                    │────▶│  (Supabase,  │
│   Claude,    │     │  ┌──────────┐  ┌───────────────┐  │     │   GitHub,    │
│   VS Code)   │◀────│  │  Policy  │  │  Interceptor  │  │◀────│   Postgres,  │
│              │     │  │  Engine  │  │  Pipeline      │  │     │   custom)    │
└──────────────┘     │  └──────────┘  └───────────────┘  │     └──────────────┘
                     │                                    │
                     │  ┌──────────┐  ┌───────────────┐  │
                     │  │  Auth    │  │  Audit Log    │  │
                     │  │  Module  │  │  (SQLite)     │  │
                     │  └──────────┘  └───────────────┘  │
                     └──────────────────────────────────┘
```

### Core components

**1. Proxy Transport Layer**
- Accepts MCP client connections (stdio and SSE transports)
- Forwards requests to upstream MCP server after policy enforcement
- Returns responses to client after response-side policy checks
- Handles both MCP stdio (spawn subprocess) and SSE (HTTP) transport modes
- Must be transparent — MCP clients should not need configuration changes beyond pointing at MCP-Guard instead of the raw server

**2. Policy Engine**
- Reads declarative YAML policy files
- Evaluates each request/response against configured policies
- Policies are composable and ordered (first-match or all-match modes)
- Supports per-server, per-tool, and per-user policy scoping

**3. Interceptor Pipeline**
- Modular middleware chain that processes requests and responses
- Each interceptor can inspect, modify, block, or log
- Built-in interceptors: auth, rate-limit, pii-detect, permission-scope, audit-log
- Extensible: users can add custom interceptors

**4. Auth Module**
- OAuth 2.1 token validation (validate tokens from external providers)
- API key validation (for simpler setups)
- mTLS client certificate validation (enterprise)
- Token injection: add auth headers to upstream MCP server requests
- Session management with configurable TTL

**5. Audit Logger**
- Logs every request/response to SQLite (default) or external sink
- Structured JSON logs with: timestamp, client ID, server name, tool called, parameters (redacted if PII), response status, latency, policy decisions
- Queryable audit trail for compliance
- Log rotation and retention policies

---

## Features by phase

### Phase 1: Core Proxy + Auth + Logging (MVP)

**P1.1 — Transparent MCP Proxy**
- Proxy stdio-based MCP servers (spawn child process, intercept stdio)
- Proxy SSE-based MCP servers (HTTP proxy)
- Configuration via YAML specifying upstream server details
- MCP protocol-aware: understand tool calls, resource reads, prompt requests
- Pass through all MCP messages transparently when no policies match

**P1.2 — Authentication**
- API key validation (simplest path — require Bearer token from client)
- OAuth 2.1 token introspection (validate tokens against external provider)
- Configurable per-server: some servers require auth, others don't
- Reject unauthorized requests with proper MCP error responses
- Token caching to avoid repeated introspection calls

**P1.3 — Audit Logging**
- Log all MCP interactions to SQLite database
- Each log entry: timestamp, direction (request/response), server, tool/resource, parameters, result status, latency, auth identity
- CLI command to query audit logs: `mcp-guard logs --server supabase --last 1h`
- Log export to JSON/CSV

**P1.4 — Basic Rate Limiting**
- Token bucket rate limiter per client identity
- Configurable limits per server and per tool
- Return proper MCP error when rate limited
- Rate limit state stored in-memory (resets on restart)

**P1.5 — Configuration**
```yaml
# mcp-guard.yaml
servers:
  supabase:
    transport: stdio
    command: npx
    args: ["-y", "@supabase/mcp-server"]
    env:
      SUPABASE_URL: "${SUPABASE_URL}"
      SUPABASE_KEY: "${SUPABASE_KEY}"
    policies:
      auth:
        type: api-key
        header: X-MCP-Guard-Key
      rate_limit:
        requests_per_minute: 60
        burst: 10
      logging:
        enabled: true
        redact_pii: true

  github:
    transport: sse
    url: "https://mcp.github.com/sse"
    policies:
      auth:
        type: oauth2
        introspection_url: "https://auth.example.com/introspect"
      permissions:
        allowed_tools:
          - "read_file"
          - "search_code"
        denied_tools:
          - "delete_repo"
          - "push_code"
      rate_limit:
        requests_per_minute: 30
```

**P1.6 — CLI Interface**
```bash
# Start the proxy
mcp-guard start                          # Start with default config
mcp-guard start --config custom.yaml     # Start with custom config
mcp-guard start --server supabase        # Proxy only one server

# Query audit logs
mcp-guard logs                           # Recent logs
mcp-guard logs --server github --last 1h # Filtered logs
mcp-guard logs --export csv > audit.csv  # Export

# Test configuration
mcp-guard validate                       # Validate config file
mcp-guard test --server supabase         # Test connection to upstream

# Status
mcp-guard status                         # Running servers, request counts, rate limit state
```

### Phase 2: PII Detection + Permission Scoping

**P2.1 — PII Detection**
- Scan MCP request parameters and response content for PII patterns
- Built-in detectors: email addresses, phone numbers, SSNs, credit card numbers, API keys/secrets
- Configurable action per PII type: redact, warn, block
- Regex-based + optional LLM-based detection for context-sensitive PII
- PII findings logged in audit trail

**P2.2 — Permission Scoping**
- Allow/deny lists for MCP tools per server
- Allow/deny lists for MCP resources per server
- Parameter-level restrictions (e.g., allow `read_file` but only for paths matching `/src/**`)
- Role-based access control: different users get different permissions
- Wildcard and regex support for tool/resource matching

**P2.3 — Dashboard (Web UI)**
- Simple web dashboard showing real-time proxy status
- Request/response timeline with filtering
- PII detection alerts
- Rate limit status per client/server
- Built with simple HTML + htmx (no heavy frontend framework)

### Phase 3: Advanced Security + Enterprise

**P3.1 — MCP Server Security Scanner**
- `mcp-guard scan <server>` — audit an MCP server for known vulnerabilities
- Check for: missing auth, insecure transport, known CVE patterns, overly permissive tool schemas, secrets in tool descriptions
- Output: security report with severity ratings and remediation suggestions
- This is the benchmarking harness we'll use for the launch blog post

**P3.2 — Threat Detection**
- Detect prompt injection attempts in tool call parameters
- Detect confused deputy attacks (agent trying to use tools beyond its scope)
- Detect data exfiltration patterns (large data extraction via tool calls)
- Anomaly detection based on historical usage patterns

**P3.3 — External Log Sinks**
- Stream audit logs to: Elasticsearch, Datadog, Splunk, CloudWatch, or any OTLP-compatible sink
- OpenTelemetry trace export for integration with existing observability stacks

---

## Tech stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Core proxy | TypeScript (Node.js) | MCP SDKs are TypeScript-first, maximum ecosystem compatibility |
| CLI framework | Commander.js or oclif | Standard Node CLI tooling |
| Config parsing | js-yaml + zod | YAML config with type-safe validation |
| Auth | jose (JWT), oauth4webapi | Standard OAuth 2.1 libraries |
| Rate limiting | Custom token bucket | No external dependencies needed |
| Audit storage | better-sqlite3 | Embedded, zero-config, fast |
| PII detection | Custom regex + optional LLM | Regex for patterns, LLM for context-sensitive |
| MCP protocol | @modelcontextprotocol/sdk | Official MCP TypeScript SDK |
| Testing | vitest | Matches PICE framework testing stack |
| Benchmarking | Custom harness (Python) | Attack simulation and performance testing |
| Packaging | Docker + npm | `npx mcp-guard start` or Docker container |

---

## Benchmarking suite (`/benchmarks`)

The benchmarks are not an afterthought — they're a core deliverable and the basis for the launch blog post.

### Security effectiveness benchmarks

```
benchmarks/
├── security/
│   ├── scenarios/
│   │   ├── credential_theft.py      # Simulate credential theft via tool calls
│   │   ├── pii_exfiltration.py      # Attempt PII extraction in responses
│   │   ├── prompt_injection.py       # Inject prompts through MCP tool params
│   │   ├── scope_escalation.py       # Attempt unauthorized tool access
│   │   ├── rate_limit_bypass.py      # Attempt to bypass rate limits
│   │   ├── redirect_uri_attack.py    # OAuth redirect URI manipulation
│   │   ├── confused_deputy.py        # Agent scope confusion attacks
│   │   ├── symlink_bypass.py         # CVE-2025-53109 pattern
│   │   ├── secret_exposure.py        # Secrets in tool descriptions/responses
│   │   └── data_exfiltration.py      # Large data extraction patterns
│   ├── servers/
│   │   ├── docker-compose.yml        # Spin up 20 popular MCP servers locally
│   │   └── server_configs/           # Config for each test server
│   ├── run_security_benchmarks.py    # Orchestrator
│   └── results/                      # Raw JSON results
```

**Target metrics:**
- 4,500+ attack simulations (450 per attack category × 10 categories)
- 20+ MCP servers tested
- Detection rate per attack category
- False positive rate per category
- Overall detection rate target: >95%

### Performance benchmarks

```
benchmarks/
├── performance/
│   ├── load_test.py               # 10,000 MCP requests through proxy
│   ├── concurrency_test.py        # Test at 1, 10, 50, 100 concurrent connections
│   ├── baseline_test.py           # Same requests direct to server (no proxy)
│   └── results/
```

**Target metrics:**
- p50/p95/p99 latency with and without MCP-Guard
- Throughput (requests/second) at various concurrency levels
- Memory and CPU usage under load
- Target: <5ms p50 overhead, <5% throughput reduction

### Compatibility benchmarks

```
benchmarks/
├── compatibility/
│   ├── test_servers.py            # Connect to each server through MCP-Guard
│   ├── server_matrix.json         # Which servers to test
│   └── results/
```

**Target:** 20/20 popular MCP servers work through MCP-Guard with zero configuration changes.

### Chart generation

```
benchmarks/
├── generate_charts.py             # matplotlib/seaborn → SVG charts for README
├── generate_tables.py             # Raw results → markdown tables for README
└── charts/                        # Generated SVGs committed to repo
    ├── detection_rate_by_category.svg
    ├── latency_overhead.svg
    ├── throughput_comparison.svg
    └── compatibility_matrix.svg
```

---

## README structure (evidence-first)

```markdown
# MCP-Guard

Security proxy for MCP servers. Adds OAuth 2.1, rate limiting, PII
detection, and audit logging to any MCP server — without modifying it.

[Demo GIF: install → configure → intercept malicious request → see audit log]

## Benchmarks

Tested against 4,500 attack simulations across 20 popular MCP servers:

- **99.X% overall detection rate** across OWASP MCP Top 10 vectors
- **+Xms p50 latency overhead** (measured across 10,000 requests)
- **20/20 MCP servers compatible** with zero configuration changes

[Detection rate chart]
[Latency overhead chart]
[Compatibility matrix table]

## Quick Start

npm install -g mcp-guard
mcp-guard init          # Generate config from your existing MCP settings
mcp-guard start         # Start the proxy

## Why MCP-Guard?

[The security problem — stats from Astrix, OWASP, CVEs]

## Configuration
## Architecture
## Full Benchmark Methodology
## Contributing
```

---

## Phased delivery

| Phase | Scope | Target |
|-------|-------|--------|
| **Phase 1** | Core proxy + auth + rate limiting + audit logging + CLI | Weeks 1–3 |
| **Benchmarks** | Security + performance + compatibility test suite | Week 4 |
| **Phase 2** | PII detection + permission scoping + web dashboard | Weeks 5–6 |
| **Launch** | README with benchmark results, blog post, Hacker News | Week 6 |
| **Phase 3** | Security scanner, threat detection, external log sinks | Post-launch |

Phase 1 + Benchmarks is the MVP. Ship it, launch it, get feedback, then build Phase 2–3 based on community interest.

---

## Success criteria

- [ ] Transparently proxies MCP stdio and SSE transports
- [ ] OAuth 2.1 and API key authentication working
- [ ] Rate limiting enforced per client/server/tool
- [ ] All MCP interactions logged to queryable SQLite audit trail
- [ ] PII detection with configurable redact/warn/block actions
- [ ] Permission scoping (tool allow/deny lists) enforced
- [ ] 4,500+ attack simulations run with >95% detection rate
- [ ] <5ms p50 latency overhead measured across 10,000 requests
- [ ] 20/20 popular MCP servers compatible
- [ ] Published to npm: `npx mcp-guard start`
- [ ] Docker image available
- [ ] Benchmark charts and tables generated and embedded in README
- [ ] Blog post: "MCP Security Is Broken: Here's What We Found Testing 20 Servers"
- [ ] Submitted to Hacker News as Show HN

---

## Open questions to brainstorm with Claude Code

1. **stdio proxy mechanism:** The MCP stdio transport works by spawning a child process and communicating over stdin/stdout. MCP-Guard needs to sit in the middle — spawn the MCP server as a child, intercept its stdio, apply policies, then present its own stdio interface to the client. What's the cleanest way to implement this bidirectional pipe interception in Node.js?

2. **MCP client configuration:** How do we make it easy for users to switch from direct MCP server connections to proxied connections? Ideally `mcp-guard init` reads their existing MCP client config (Claude Desktop `claude_desktop_config.json`, Cursor settings, etc.) and generates the MCP-Guard config automatically, then rewrites their client config to point at MCP-Guard.

3. **PII detection accuracy vs. performance:** Regex-based PII detection is fast but produces false positives. LLM-based detection is accurate but adds latency and cost. Should we default to regex with an opt-in LLM mode, or use a tiered approach (regex first, LLM only when regex is uncertain)?

4. **State persistence for rate limiting:** In-memory rate limit state resets on restart. Should we persist to SQLite alongside audit logs, or is in-memory acceptable for v1?

5. **Multi-server proxy:** Should MCP-Guard run as one process proxying multiple servers, or one process per server? One process is simpler to manage but creates a single point of failure. One per server is more isolated but harder to configure.

6. **Benchmark reproducibility:** The security benchmarks need to spin up 20 MCP servers. Docker Compose is the obvious choice, but some MCP servers require API keys or external services. How do we handle servers that need real credentials in a reproducible benchmark suite?
