# Changelog

All notable changes follow Semantic Versioning.

## [2.0.0] - 2026-08-25

### Added

- Multi-scanner detection engine with normalized findings and per-scanner health.
- Gitleaks, Semgrep, Trivy, Checkov, Syft and Grype adapters.
- CycloneDX SBOM generation and live OSV batch correlation.
- Persistent advisory catalog, scanner registry and v2 scan history.
- Signed, idempotent GitHub push and pull-request webhooks.
- GitHub App installation-token authentication for private repositories.
- Bounded execution, timeouts, output limits and graceful scanner degradation.
- Full scanner container image and eleven automated tests.

### Changed

- Dashboard scans now use the v2 engine.
- Health endpoint reports engine version 2.0.0.

## [1.0.0] - 2026-08-25

- Native deterministic rules, policy evaluation, dashboard and SARIF export.
