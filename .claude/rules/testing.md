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

### Mocking
- Use `vi.mock()` for module-level mocks (e.g., mocking koffi for peer creds on non-Unix)
- Use `vi.fn()` for function-level mocks
- Prefer real implementations over mocks when practical (especially for SQLite — use in-memory databases)
- Never mock the interceptor pipeline in pipeline tests — test the real chain

## Naming

- Describe blocks: module or class name
- Test names: describe behavior, not implementation (`'blocks request when auth fails'` not `'calls blockHandler'`)
