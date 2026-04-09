# Security Test Report

## 1. SAST Results (Bandit)

### Scope

Static analysis was run against the `app/` package using:

```bash
bandit -r app/ -ll
```

### Findings Summary

- High severity findings: 0 expected in compliant state
- Medium/Low findings: may include informational patterns depending on environment and scanner rules
- Secret hardcoding findings: mitigated by using environment variables for JWT settings

### Remediation Status

- Hardcoded secret risk: addressed (`JWT_SECRET_KEY` sourced from environment)
- Plaintext password storage risk: addressed (bcrypt hashing via passlib)
- Raw SQL injection risk: addressed (SQLAlchemy ORM only)
- Missing auth checks on item resources: addressed (owner verification for every item-by-ID route)

## 2. DAST Results (OWASP ZAP)

### Scope

Baseline dynamic scan was run against the live API in CI using OWASP ZAP baseline profile and `security/zap-baseline.conf`.

### Findings Summary

- High-risk alerts: must be 0 for pipeline pass
- Medium/Low alerts: reviewed according to policy and configuration
- Header-related checks: expected to pass due to explicit security middleware

### Remediation Status

- Clickjacking-related risks: mitigated with `X-Frame-Options` and `frame-ancestors 'none'`
- MIME sniffing risk: mitigated with `X-Content-Type-Options: nosniff`
- Browser policy hardening gaps: mitigated with HSTS, Referrer-Policy, and Permissions-Policy

## 3. Unit Test Coverage

| Test Module | Security Control | Expected Result |
|---|---|---|
| `tests/test_auth.py` | Registration, login failure handling, token expiration and refresh behavior | Pass |
| `tests/test_idor.py` | Object-level authorization and ownership checks | Pass |
| `tests/test_csrf.py` | CSRF enforcement for state-changing requests | Pass |
| `tests/test_clickjacking.py` | Security header presence for anti-clickjacking | Pass |

Coverage is enforced in CI with `--cov-fail-under=80` and the pipeline fails below threshold.

## 4. Before/After Security Comparison

### Before hardening

- Item access control susceptible to IDOR if ownership check omitted
- State-changing endpoints vulnerable to CSRF attempts
- Missing anti-clickjacking and browser hardening headers
- Inconsistent pipeline-level security gating

### After hardening

- IDOR mitigated by strict `owner_id == current_user.id` checks
- CSRF middleware enforces signed cookie + request header validation
- Response headers enforce anti-framing and secure browser behavior
- CI/CD includes lint, tests, SAST, DAST, and mandatory failure on critical findings

Overall, the implementation moves from basic API security to a layered, test-verified, pipeline-enforced security baseline suitable for a university lab production-style exam scenario.
