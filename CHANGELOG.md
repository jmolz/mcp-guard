# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-04-07

### Added
- Core daemon with Unix socket server and auto-start
- Thin bridge process (structurally fail-closed)
- Interceptor pipeline: Auth, Rate Limit, Permissions, Sampling Guard, PII Detect
- PII detection with regex detector (email, phone, SSN, credit card with Luhn, AWS key, GitHub token)
- Bidirectional PII scanning (request and response)
- Capability filtering (denied tools/resources removed from initialize response)
- SQLite audit logging with WAL mode
- Config system with YAML, Zod validation, env var interpolation
- Config composability via `extends` with SHA-256 pinning
- Floor-based config merge (personal configs can only restrict, never relax)
- Hot config reload via file watcher
- OAuth 2.1 authentication with PKCE and claims-to-role mapping
- Role-based effective policy resolution
- SSE and Streamable HTTP transport support
- Dashboard HTTP server with health endpoint
- SQLCipher encryption at rest (optional)
- CLI: start, stop, connect, status, health, validate, logs, auth login/status/logout, init
- `mcp-guard init` command to auto-discover existing MCP client configs
- Benchmark infrastructure: 8 mock servers, 10 security categories, 4,500+ attack scenarios
- Legitimate traffic baseline: 10,000+ benign requests
- Performance benchmarks: latency, concurrency, throughput
- SVG chart and markdown table report generation
- Docker image and docker-compose
- CI/CD: release, benchmark, and security scanning workflows
