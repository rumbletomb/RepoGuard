# Advisory database and OSV

RepoGuard maintains a local, queryable advisory catalog enriched from the public OSV API. Syft generates a CycloneDX SBOM; RepoGuard extracts at most 1,000 named/versioned components and submits an OSV batch query. Matching advisory details are normalized and upserted by advisory ID plus package.

## Stored fields

- advisory ID and aliases such as CVE identifiers
- package and ecosystem
- affected range when supplied by an adapter
- normalized severity
- summary
- upstream modification time
- source (`OSV`)

The catalog is available at `GET /api/v2/advisories?query=...`. It is updated during scans, so it reflects vulnerabilities relevant to analyzed software rather than mirroring the complete OSV corpus.

## Availability behavior

OSV network failure never discards scanner results. Enrichment returns no additional findings and emits a structured warning without package contents or credentials. Grype and Trivy still provide their locally cached databases.

## Production refresh policy

- Allow outbound HTTPS only to required scanner and advisory endpoints.
- Persist Trivy/Grype caches on a dedicated volume in high-volume deployments.
- Track database age and alert when feeds are stale.
- Schedule a representative SBOM re-scan daily to refresh relevant advisories.
- Keep original scanner identifiers and upstream timestamps for auditability.

RepoGuard does not assert that a package match is exploitable. A CVE match is a triage finding; reachability and compensating controls require validation.
