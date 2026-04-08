---
paths:
  - ".github/workflows/release.yml"
  - "package.json"
  - "docker/**"
  - "README.md"
  - "SECURITY.md"
  - "CODE_OF_CONDUCT.md"
---

# Publishing & Release Readiness Rules

## Lesson Learned

Phase 5B built all the release infrastructure (CI/CD workflows, Docker, npm config, docs) but missed the external prerequisites. The first push to GitHub failed 3 times because of missing `packageManager` field, cross-platform test failures, and benchmark threshold mismatch. The npm publish then failed because no NPM_TOKEN secret was configured. The repo had no branch protection. Documentation referenced a nonexistent email domain.

**These are not afterthoughts — they are first-class requirements that must appear in any launch/publish plan.**

## PRD and Launch Plan Requirements

When writing a PRD or plan that includes publishing to any registry (npm, PyPI, Docker Hub, GHCR, crates.io, etc.), the plan **must include** these as explicit prerequisites with their own tasks:

### External Account Prerequisites

- [ ] Registry account exists (npm, GHCR, etc.) with correct email
- [ ] Authentication tokens/secrets created and stored
- [ ] GitHub repo secrets configured (`NPM_TOKEN`, `DOCKER_PASSWORD`, etc.)
- [ ] GitHub Actions permissions set (`contents: write`, `packages: write`, etc.)

### Repository Configuration Prerequisites

- [ ] Branch protection rules configured (prevent force push, require status checks)
- [ ] `packageManager` field in package.json (required by pnpm/action-setup)
- [ ] Author/email references in all docs use real, verified addresses
- [ ] CI workflow action versions are current (not deprecated)
- [ ] Dependabot configuration reviewed (auto-PRs for major versions may need manual evaluation)

### CI/CD Validation Prerequisites

- [ ] Tests pass on the CI platform (Linux), not just locally (macOS)
- [ ] Platform-specific code paths have cross-platform test coverage
- [ ] Benchmark thresholds account for quick-mode sampling variance
- [ ] Release workflow has been dry-run tested (tag a pre-release first)

### Documentation Prerequisites

- [ ] Contact emails in SECURITY.md, CODE_OF_CONDUCT.md are real and monitored
- [ ] README includes actual benchmark numbers, not just targets
- [ ] LICENSE file exists and matches package.json `license` field

## Pre-First-Publish Checklist

Before tagging the first release:

1. **Dry-run the release locally**: `npm pack --dry-run`, `docker build`
2. **Verify secrets**: `gh secret list --repo <repo>` shows all required tokens
3. **Test CI end-to-end**: Push a commit, verify all workflow jobs pass
4. **Pre-release tag**: Tag `v0.1.0-rc.1` first to test the release workflow without publishing
5. **Branch protection**: Verify with `gh api repos/{owner}/{repo}/rulesets`
6. **Email audit**: `grep -r '@' *.md` — every email must be real and reachable

## Why This Matters

Code that passes every test locally but fails CI on first push erodes trust in the release process. A launch plan that omits infrastructure prerequisites will always produce a "fix CI, re-tag, re-push" cycle on day one. These requirements are predictable and should be planned, not discovered.
