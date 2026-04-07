---
paths:
  - ".github/workflows/**"
  - "package.json"
---

# CI/CD Rules

## package.json Requirements

- **`packageManager` field is required**: `pnpm/action-setup@v4+` reads this to determine the pnpm version. Without it, CI fails immediately. Format: `"packageManager": "pnpm@<version>"`. Keep in sync with the local pnpm version.
- **`engines.node` must match workflow `node-version`**: Both must specify Node 22+.

## Workflow Conventions

- All workflows using pnpm must include the `pnpm/action-setup` step (reads `packageManager` from `package.json`).
- The `actions/setup-node` step must use `cache: pnpm` for faster installs.
- After `pnpm install --frozen-lockfile`, run the validation commands.

## Benchmark Thresholds in CI

- **Quick-mode detection rate is inherently lower** than the full suite due to stratified sampling (~50 per category vs 450+).
- Release workflow uses `--min-detection 0.85` for quick mode to account for sampling variance.
- The default threshold (95%) applies to full benchmark runs.
- Never raise the quick-mode CI threshold above 0.90 — sampling noise makes it unreliable above that.

## Cross-Platform Compatibility

- CI runs on `ubuntu-latest` (Linux). Local dev is macOS.
- Tests that use platform-specific paths (e.g., `~/Library/Application Support/`) must mock `node:os` to ensure deterministic behavior on all platforms.
- Never assume `process.platform === 'darwin'` in tests unless explicitly mocking.

## Pre-Push Checklist

Before pushing changes that affect CI:
1. Verify `packageManager` field exists and matches `pnpm --version`
2. Run `pnpm lint && pnpm typecheck && pnpm test && pnpm build` locally
3. Check that tests don't depend on macOS-specific filesystem paths without mocking
4. If modifying workflow files, verify no untrusted input is used directly in `run:` commands
