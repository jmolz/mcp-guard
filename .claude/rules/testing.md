---
paths:
  - "tests/**"
  - "**/*.test.ts"
  - "**/*.spec.ts"
---

# Testing Rules

## Framework & Structure

- **vitest** for all tests
- Tests live in `tests/` mirroring `src/` (e.g., `src/interceptors/pipeline.ts` → `tests/interceptors/pipeline.test.ts`)
- Test fixtures in `tests/fixtures/` (sample configs, MCP messages, mock server responses)

## What to Test

### Every module needs at minimum:
1. **Happy path**: Normal operation produces correct output
2. **Edge case**: Boundary conditions, empty inputs, max values
3. **Error/failure case**: What happens when things go wrong

### Security-critical code requires additional negative tests:
- **Interceptor pipeline**: Prove that a thrown error results in BLOCK, not PASS
- **PII redaction**: Prove that original values are absent from the output and audit log
- **Auth**: Prove that invalid credentials result in rejection
- **Config merger**: Prove that relaxing a base policy is impossible
- **Permissions**: Prove that denied tools are absent from capability list AND blocked at call time

## Patterns

### Unit Tests (pure logic)
```typescript
describe('RegexDetector', () => {
  it('detects email addresses', () => { /* ... */ });
  it('rejects non-email strings', () => { /* ... */ });
  it('validates credit cards with Luhn', () => { /* ... */ });
});
```

### Integration Tests (process interaction)
- Spawn real daemon and bridge processes for end-to-end flow tests
- Use temp directories for Unix sockets, SQLite databases, and config files
- Clean up after each test (afterEach/afterAll hooks)
- Set short timeouts for daemon auto-start tests
- Two E2E patterns:
  - **In-process daemon**: Call `startDaemon(config)` directly in test (faster, easier to debug)
  - **Process-spawned daemon**: Spawn `npx tsx src/cli.ts start --config <path>` as a detached child (tests real CLI flow)
- Use `tests/fixtures/bridge-connect-helper.ts` for process-level bridge tests (wrong key → exit 1)

### Shared Test Helpers
- `tests/fixtures/framing.ts` — `writeFramed()`, `readFramed()`, `connectSocket()` for socket protocol
- `tests/fixtures/mock-mcp-server.ts` — Standalone MCP server for upstream testing
- `tests/fixtures/bridge-connect-helper.ts` — Spawnable bridge script with env-var path overrides
- **Never duplicate** test helpers across files — import from `tests/fixtures/`

### Mocking
- Use `vi.mock()` for module-level mocks (e.g., mocking koffi for peer creds on non-Unix)
- Use `vi.fn()` for function-level mocks
- Prefer real implementations over mocks when practical (especially for SQLite — use in-memory databases)
- Never mock the interceptor pipeline in pipeline tests — test the real chain

### E2E Test Isolation
- **Dashboard port**: Always use `dashboard_port: 0` in test configs — OS assigns ephemeral port, prevents parallel test conflicts
- **Actual port discovery**: Use `daemonHandle.getDashboardPort()` to get the OS-assigned port for HTTP assertions
- **HTTP test servers**: For fetcher/extends tests, spin up `node:http` servers on port 0 — `server.address().port` gives the actual port
- **Temp directories**: `mkdtemp(join(tmpdir(), 'mcp-guard-{testname}-'))` for full isolation; clean up in `afterEach`/`afterAll`

### Security-Critical Negative Tests
Beyond the general negative test requirement, these modules have specific negative patterns:
- **Config merger**: Each relaxation direction must have a test proving it fails (10 negative tests in `merger.test.ts`)
- **Config fetcher**: Hash mismatch on live fetch must NOT fall back to cache — separate test from cache-miss scenario
- **PII custom types**: Personal cannot weaken base type patterns or actions — test proves union + stricter action
- **Locked policies**: Test that the *entire* personal policy is ignored, not just individual fields

### Benchmark Tests
- Benchmark tests live in `tests/benchmarks/` (not `benchmarks/` — keep test files under `tests/`)
- `generators.test.ts` — validates scenario counts (≥450 per category), structure, Luhn CCs, zero PII in legitimate traffic, quick mode coverage
- `mock-servers.test.ts` — spawns each mock server, sends `initialize` + `tools/list`, verifies expected tool names
- Call `resetIdCounter()` in `beforeEach` to ensure deterministic JSON-RPC IDs across test runs
- Mock server tests must have `afterAll` cleanup hooks to kill spawned child processes

### Tier 2 Compatibility Tests
- Live in `tests/compat/tier2.test.ts` — tests MCP-Guard against real open-source MCP servers
- Env-gated: `MCP_GUARD_TIER2=1 pnpm vitest run tests/compat/tier2.test.ts`
- Excluded from the default `pnpm test` and the regression suite (requires real server processes + network)
- Each server tests: `initialize`, `tools/list`, and one `tools/call`
- Use `sampleCall` field in `ServerSpec` for deterministic tool calls
- Tests use strong assertions: `expect(result).toBeDefined()` + `expect(error).toBeUndefined()`

### CLI Tests
- `tests/cli/init.test.ts` — mock filesystem via `vi.mock('node:fs/promises')`
- Never touch real client config files — all paths are mocked
- Test that `writeFile` is only ever called with the `--output` path, never client config paths

### Cross-Platform Test Requirements
- CI runs on Linux (`ubuntu-latest`), local dev is macOS. Tests must pass on both.
- Tests using platform-specific paths (e.g., `~/Library/Application Support/`) must mock `node:os` so `platform()` returns the expected value (typically `'darwin'`).
- `init.test.ts` mocks `node:os` to return `platform: 'darwin'` — the fixture paths match the macOS branch in `getClientConfigs()`.
- Any new test that depends on `os.platform()`, `os.homedir()`, or conditional path logic must include an explicit `vi.mock('node:os')` to be deterministic.

## Naming

- Describe blocks: module or class name
- Test names: describe behavior, not implementation (`'blocks request when auth fails'` not `'calls blockHandler'`)
