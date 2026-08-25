# Native rule catalog

The native analyzer provides useful zero-configuration checks. Pattern rules are triage signals, not proof of exploitability; review findings before remediation or accepted-risk decisions.

| Rule | Severity | Category | Detects | Recommended action |
|---|---:|---|---|---|
| RG001 | Critical | secret | PEM private-key header | Revoke, rotate, purge history, use secret storage |
| RG002 | Critical | secret | AWS access-key identifier | Revoke and rotate; prefer workload identity |
| RG003 | High | secret | Literal assigned to credential-like key | Move to secret manager/environment injection |
| RG101 | High | sast | SQL built with concatenation/interpolation | Use parameterized queries |
| RG102 | High | sast | Calls to `eval` or `exec` | Use an explicit parser or allow-list |
| RG201 | Medium | configuration | Non-local plain HTTP URL | Require HTTPS and certificate validation |
| RG301 | Medium | container | `FROM image:latest` | Pin a version or immutable digest |
| RG302 | High | container | `privileged: true` | Drop privileged mode and minimize capabilities |

## Exclusions and limits

Directories named `.git`, `node_modules`, `bin`, `obj`, `vendor`, `.next`, `dist`, or `coverage` are excluded anywhere in the tree. Common binaries and archives are ignored. Individual files over 2 MiB are skipped and scans over 20,000 enumerated files fail safely.

## Fingerprints

The fingerprint is the first 96 bits of SHA-256 over rule ID, normalized relative path, and trimmed matching line. It is stable when the evidence remains on the same path and changes when the risky line changes. It contains no plaintext secret.

## False-positive handling

The API model supports `Open`, `Accepted`, and `Resolved` states. Version 1.0 preserves status in scan results but intentionally does not expose mutation through the dashboard. An enterprise implementation should require a reason, reviewer, and expiry for accepted risk rather than silently suppressing it.

## Extending rules

Add a generated regular expression and invoke `AddMatches` from `AnalyzeFile`. Every rule must have:

1. A stable identifier.
2. Category and calibrated severity.
3. Concise evidence description.
4. Actionable remediation.
5. Positive and negative tests.

For language-aware data flow, dependency CVEs, and IaC semantics, prefer external adapters rather than complex regular expressions.
