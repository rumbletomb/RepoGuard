# REST API reference

Base path: `/api`. Content type is `application/json`. Dates use ISO 8601 UTC. Enum values are strings.

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
