# REST API reference

Base path: `/api`. Content type is `application/json`. Dates use ISO 8601 UTC. Enum values are strings.

Version 2 endpoints use `/api/v2`; original v1 endpoints remain compatible.

## Health and dashboard

### `GET /api/health`

Returns process health and release version. A `200` response is suitable for a container liveness check.

### `GET /api/dashboard`

Returns aggregate repository and scan counts plus the latest complete scan.

## Repositories

### `GET /api/repositories`

Lists registered repositories.

### `POST /api/repositories`

Request:

```json
{ "name": "payments-api", "path": "/repositories/payments-api" }
```

Returns `201 Created`, `404` if the directory is unavailable, or `400` for missing input. The path is normalized to an absolute path.

### `DELETE /api/repositories/{repositoryId}`

Removes a registration but preserves historical scans. Returns `204` or `404`.

## Scans

### `POST /api/repositories/{repositoryId}/scans`

Request:

```json
{ "commit": "7d3d0ae" }
```

`commit` is optional metadata; the community scanner examines the directory's current contents. Response:

```json
{
  "id": "...",
  "repositoryId": "...",
  "status": "failed",
  "filesScanned": 14,
  "findings": [{
    "fingerprint": "f118c6...",
    "ruleId": "RG003",
    "category": "secret",
    "severity": "High",
    "title": "Hard-coded credential",
    "file": "app.py",
    "line": 4,
    "remediation": "Read credentials from a secret manager or environment injection.",
    "status": "Open"
  }],
  "policy": { "passed": false, "violations": ["High findings: 1 (maximum 0)."] }
}
```

Safety errors such as excessive file counts return problem details. Client cancellation cancels the scan.

### `GET /api/scans`

Lists scans newest first.

### `GET /api/scans/{scanId}`

Returns a single scan or `404`.

### `GET /api/scans/{scanId}/sarif`

Returns SARIF 2.1.0. Save it as `repoguard.sarif` for upload to GitHub code scanning or ingestion by compatible tools.

## Policy

### `GET /api/policy`

Returns the current global policy.

### `PUT /api/policy`

```json
{ "maxCritical": 0, "maxHigh": 2, "blockSecrets": true }
```

Thresholds count open findings. Negative thresholds return `400`. The updated policy applies to subsequent scans; historical scan decisions remain immutable.

## Error semantics

- `400`: invalid request or policy
- `404`: repository, scan, or directory not found
- `500`: unexpected internal error, represented as problem details

Policy failure is not an HTTP error. Inspect `scan.policy.passed` or `scan.status`.

## Version 2 engine

### `POST /api/v2/repositories/{repositoryId}/scans`

Runs the native engine, Syft, Gitleaks, Semgrep, Trivy, Checkov, Grype and OSV correlation. The response is a `ScanEnvelope` containing normalized findings, policy result, scanner health/duration and the relative SBOM artifact path.

### `GET /api/v2/scans` and `GET /api/v2/scans/{scanId}`

List or retrieve v2 scan envelopes.

### `GET /api/v2/scans/{scanId}/sarif`

Exports normalized v2 findings as SARIF 2.1.0.

### `GET /api/v2/scans/{scanId}/sbom`

Downloads the scan CycloneDX JSON SBOM when Syft completed successfully. Artifact paths are resolved beneath the configured artifact root.

### `GET /api/v2/advisories?query=<id-or-package>`

Search the persistent catalog populated from OSV matches.

### `GET /api/v2/rules`

Returns the versioned registry of native and external detection sources.

### `GET /api/v2/webhook-jobs`

Returns GitHub job lifecycle records.

### `POST /api/webhooks/github`

Receives GitHub `push` and `pull_request` events. Requires valid `X-Hub-Signature-256`, uses `X-GitHub-Delivery` for idempotency and returns `202 Accepted` when queued.
