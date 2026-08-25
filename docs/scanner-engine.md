# Scanner engine

## Pipeline

```text
repository
  ├─ native baseline
  ├─ Syft ──> CycloneDX SBOM ──> Grype
  │                             └─> OSV API
  ├─ Gitleaks
  ├─ Semgrep
  ├─ Trivy
  └─ Checkov
          ↓
 normalization → fingerprinting → deduplication → policy → persistence
```

Syft runs first so Grype and OSV can consume its SBOM. Other adapters then run sequentially in the community deployment to bound peak resources. A future distributed worker can parallelize independent adapters without changing their contract.

## Adapter contract

Every adapter returns its name, version, status, elapsed milliseconds, findings, optional error and optional SBOM path. Valid statuses are `completed`, `unavailable`, and `error`. One failed tool does not discard other results.

Findings converge on a stable model: fingerprint, external rule ID, category, severity, title, description, normalized relative path, line, remediation and lifecycle status.

## Tool responsibilities

| Tool | Primary responsibility |
|---|---|
| Native | Fast deterministic baseline with no external dependency |
| Gitleaks | Credential and secret discovery with redacted output |
| Semgrep | Language-aware static application security testing |
| Trivy | Dependency CVEs, filesystem secrets and configuration |
| Checkov | Terraform, Kubernetes and cloud infrastructure policies |
| Syft | CycloneDX software bill of materials |
| Grype | Vulnerability correlation from SBOM/packages |
| OSV | Live ecosystem advisory correlation and catalog enrichment |

## Execution safety

- Process arguments use `ProcessStartInfo.ArgumentList`; no shell interpolation occurs.
- Each tool has a hard timeout.
- Captured output is limited to 20 MB.
- Gitleaks output is redacted.
- Scanner stderr is not exposed as source evidence.
- Repository code is not invoked by RepoGuard.
- Git checkout directories are unique and deleted after jobs.

External scanners still parse attacker-controlled files. For hostile public repositories, run scan workers in disposable rootless containers with CPU, memory, PID, disk, time and egress limits.

## Adding an adapter

Implement `IScannerAdapter`, invoke the binary through `SafeCommandRunner`, parse a bounded machine format and create normalized results through `FindingFactory`. Register the adapter in dependency injection and add parser fixtures covering malformed, empty and representative output.
