# MCP-Guard Benchmark Report

Generated: 2026-04-08T15:51:21.304Z

## Verdict

| Suite | Result | Details |
|-------|--------|---------|
| Security | ✅ PASS | 97.0% detection (target >95%) |
| Audit Integrity | ✅ PASS | No raw PII in audit logs |
| False Positives | ✅ PASS | 0.000% FP rate (target <0.1%) |
| Performance | ✅ PASS | p50 0.17ms (target <5ms) |

## Security Detection

![Security Detection Rates](../charts/security-detection.svg)

| Category | Scenarios | Detected | Rate | Status |
|----------|-----------|----------|------|--------|
| rate_limit_evasion | 554 | 512 | 92.4% | ❌ |
| permission_bypass | 744 | 736 | 98.9% | ✅ |
| resource_traversal | 571 | 545 | 95.4% | ✅ |
| pii_request_leak | 1170 | 1098 | 93.8% | ❌ |
| pii_response_leak | 480 | 480 | 100.0% | ✅ |
| auth_bypass | 464 | 464 | 100.0% | ✅ |
| sampling_injection | 484 | 484 | 100.0% | ✅ |
| config_override | 1024 | 1024 | 100.0% | ✅ |
| capability_probe | 692 | 674 | 97.4% | ✅ |
| pii_evasion | 912 | 864 | 94.7% | ❌ |
| **OVERALL** | **7095** | **6881** | **97.0%** | ✅ |

## False Positives

![False Positive Rate](../charts/false-positive.svg)

- Total requests: 10168
- False positives: 0
- FP rate: 0.000%

## Performance

![Latency Distribution](../charts/latency.svg)

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| p50 latency | 0.17 ms | <5 ms | ✅ |
| p95 latency | 0.32 ms | — | ℹ️ |
| p99 latency | 1.41 ms | — | ℹ️ |
| Mean latency | 0.21 ms | — | ℹ️ |
| Throughput | 6988 req/s | — | ℹ️ |

### Concurrency Scaling

![Concurrency Scaling](../charts/concurrency.svg)

| Connections | p50 (ms) | p95 (ms) | p99 (ms) |
|-------------|----------|----------|----------|
| 1 | 0.15 | 0.22 | 1.55 |
| 10 | 1.19 | 3.08 | 7.18 |
| 50 | 7.28 | 8.63 | 9.45 |
| 100 | 14.45 | 17.75 | 20.52 |
