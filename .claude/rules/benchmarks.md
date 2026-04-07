---
paths:
  - "benchmarks/**"
  - "tests/benchmarks/**"
---

# Benchmark Rules

## Architecture

The benchmark suite tests MCP-Guard's interceptor pipeline against 4,500+ attack scenarios, 10,000+ legitimate requests, and performance baselines. It uses **in-process daemon testing** via `startDaemon(config)` — no CLI subprocess spawning.

### Three Benchmark Suites

1. **Security** (`benchmarks/security/`) — 10 attack categories, each with a scenario generator producing 450+ scenarios via combinatorial axes (tools x servers x techniques). Measures detection rate.
2. **Legitimate** (`benchmarks/legitimate/`) — 10,000+ benign requests across all 8 mock servers. Measures false positive rate.
3. **Performance** (`benchmarks/performance/`) — Latency (p50/p95/p99), concurrency (1/10/50/100 connections), throughput.

### Mock Servers

8 archetypes in `benchmarks/mock-servers/`, each registering domain-specific tools:
- Every server (except sampling-server before the fix) must call `registerBenchmarkPiiTool(server)` from `base.ts` — this is how `pii_response_leak` scenarios work.
- Mock server responses must be deterministic (no randomness, no timestamps that change).
- `PII_RESPONSE_DATA` in `base.ts` is the canonical set of PII values for response-side testing.

## Key Patterns Learned

### Expected Decisions

- **Request-side PII redaction is transparent to clients**: The PII interceptor redacts content before forwarding to upstream, but the client receives a normal response. From the benchmark runner's perspective (client side), redact-action PII types result in **PASS**, not MODIFY.
- **Response-side PII redaction is visible**: The client sees `[REDACTED:type]` markers in the response → **MODIFY**.
- **PII block types (ssn, credit_card) → BLOCK**. PII redact types (email, phone, aws_key, github_token) → **PASS** on requests, **MODIFY** on responses.

### Per-Server Denied Tools

Denied tools are per-server, not global. Use `DENIED_TOOLS_PER_SERVER` from `generator.ts` and `isToolDeniedOnServer(tool, server)` to check. Sending a denied tool to a server that doesn't deny it should expect **PASS**, not BLOCK.

### Glob Matching

The permissions interceptor converts `*` to `[^/]*` (single-level, not recursive). Multi-level paths like `db://schema/users/passwords` do NOT match `db://schema/*`. Factor this into `resource-traversal` expected decisions.

### Rate Limit State

- Rate limits are keyed by `(server, username, tool)` for per-tool limits and `(server, username)` for server-level RPM.
- **Burst groups must run FIRST** before other categories to avoid server-level RPM bucket contamination.
- Use only **one tool per server** for RPM burst testing — multiple burst groups on the same server share the server-level bucket.
- Each burst group gets its own socket, but they share the daemon's rate-limit store.

### PII Evasion Transforms

When a transform has no effect on the PII value (e.g., Cyrillic letter replacement on digit-only SSN/CC), the original PII is still present and will be detected. Use a `valueChanged` check to set the correct expected decision.

## Adding New Scenarios

### New Security Category

1. Create `benchmarks/security/categories/{category-name}.ts`
2. Implement `ScenarioGenerator` interface (or `BurstGroupGenerator` for rate-limit-style tests)
3. Generate 450+ scenarios via combinatorial axes
4. Register in `benchmarks/security/run-security.ts`
5. Add to `tests/benchmarks/generators.test.ts`

### New Mock Server

1. Create `benchmarks/mock-servers/{name}.ts`
2. Use `createMockServer()` from `base.ts`
3. Call `registerBenchmarkPiiTool(server)` for PII response testing
4. Add to `MOCK_SERVERS` in `generator.ts`
5. Add to `tests/benchmarks/mock-servers.test.ts` with expected tools

## SQL Safety in Benchmarks

- The audit integrity check uses parameterized SQL with `LIKE ? ESCAPE '\'`
- PII values must have `%` and `_` escaped before use in LIKE patterns (these are SQL wildcards)
- Never use string interpolation in SQL, even in benchmark code — it sets a bad pattern

## Quick Mode

`--quick` uses `stratifiedSample()` to pick evenly-spaced items from each category (~50 per category, ~500 legitimate). This ensures full category coverage with ~30s runtime instead of 5-10 minutes.

## Report Generation

After writing `latest.json`, the runner calls `generateReport(result)` from `benchmarks/report/index.ts` to produce:
- 4 SVG charts in `benchmarks/charts/` (security-detection, latency, concurrency, false-positive)
- 3 markdown tables in `benchmarks/tables/` (security, performance, concurrency)
- Combined report at `benchmarks/results/REPORT.md`

Skip with `--no-report` flag. Charts use template-literal SVG (no external dependencies). Tests in `tests/benchmarks/report.test.ts`.

## Runner Exit Code

The runner exits non-zero when ANY threshold is breached (detection rate < 95%, FP rate >= 0.1%, p50 >= 5ms, audit integrity failed). This makes it CI-ready.

## Content Safety in Legitimate Traffic

- Legitimate scenario request params must contain **zero PII** at any confidence level
- Mock server responses called by legitimate traffic must also be PII-free (no emails, phones, SSNs in tool responses)
- Use `SAFE_TEXTS` and `NEAR_PII_TEXTS` arrays — every entry must be verified against the regex detector
- Avoid numbers with 10+ consecutive digits (matches phone regex)
- The `_benchmark_pii` tool is for security benchmarks only — never include it in legitimate traffic
