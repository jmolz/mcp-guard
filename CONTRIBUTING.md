# Contributing to MCP-Guard

Thank you for your interest in contributing to MCP-Guard!

## Getting Started

```bash
git clone https://github.com/jmolz/mcp-guard.git
cd mcp-guard
pnpm install
```

## Development Commands

| Command | Description |
|---------|-------------|
| `pnpm dev` | Start daemon in dev mode (tsx watch) |
| `pnpm build` | Production build (tsup) |
| `pnpm test` | Run test suite |
| `pnpm lint` | ESLint check |
| `pnpm typecheck` | TypeScript type checking |
| `pnpm benchmark:quick` | Quick benchmark suite (~30s) |

## Before Every Commit

```bash
pnpm lint && pnpm typecheck && pnpm test && pnpm build
```

## Architecture Overview

MCP-Guard uses three process types:

- **Daemon** — Long-running process managing upstream connections and the interceptor pipeline
- **Bridge** — Thin stdio relay (zero policy logic, structurally fail-closed)
- **CLI** — Stateless management commands

The interceptor pipeline runs in fixed order: Auth, Rate Limit, Permissions, Sampling Guard, PII Detect.

See `CLAUDE.md` for detailed architecture documentation.

## Making Changes

1. Branch from `main`
2. Write tests for your changes
3. Run the full validation suite
4. Submit a PR

## Adding an Interceptor

1. Define your interceptor implementing the `Interceptor` interface in `src/interceptors/types.ts`
2. Implement the interceptor in `src/interceptors/your-interceptor.ts`
3. Write tests in `tests/interceptors/your-interceptor.test.ts`
4. Wire it into the pipeline in `src/interceptors/pipeline.ts`
5. Add benchmark scenarios in `benchmarks/security/categories/`

## Adding Benchmark Scenarios

See `.claude/rules/benchmarks.md` for the full guide on adding security categories and mock servers.

## PR Requirements

- All validation commands pass
- Tests cover happy path, edge case, and error case
- Security-critical code includes negative tests
- No `any` types without `// SAFETY:` justification

## Release Process

Releases are automated via GitHub Actions. Pushing a `v*` tag triggers:
- npm publish
- Docker image push to GHCR
- GitHub Release creation

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
