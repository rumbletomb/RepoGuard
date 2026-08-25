# Architecture and design

## Context

RepoGuard turns repository contents into normalized findings and an auditable release-policy decision. The first release favors an operationally simple modular monolith: one deployable process, zero external state services, and explicit seams for future scanner and database adapters.

```text
Browser / CI client
        |
        v
ASP.NET Core HTTP API ---- static dashboard
        |
        +---- repository service
        |          |
        |          v
        |     native analyzer ---- read-only repository
        |
        +---- policy evaluator
        +---- SARIF exporter
        +---- atomic JSON store ---- persistent volume
```

## Scan lifecycle

1. An administrator registers a name and an absolute repository directory.
2. RepoGuard resolves and validates the directory.
3. A scan enumerates at most 20,000 files while excluding generated and vendor directories.
4. Binary and files above 2 MiB are skipped.
5. Text is inspected by compiled native rules. Repository contents are never executed.
6. Duplicates are removed using a SHA-256-derived fingerprint of rule, path, and evidence.
7. The policy evaluator counts open findings and produces explicit violations.
8. Scan and policy results are atomically persisted.
9. Consumers retrieve JSON or SARIF 2.1.0.

## Modules

### HTTP/API

`Program.cs` defines a small REST surface using ASP.NET Core minimal APIs. Responses use JSON enums and RFC 9457 problem details for unhandled failures. Static assets and API are same-origin, avoiding CORS configuration.

### Analyzer

`RepositoryAnalyzer` is deterministic and stateless. Rules are compiled at build time with `GeneratedRegex`. Adding external scanners should use an `IScanner` adapter returning `Finding` values; the evaluator and exporters then remain unchanged.

### Policy

Policy is deliberately separate from detection. A scan can complete while failing policy. This distinction makes HTTP/API reliability independent of the release decision and works cleanly in CI.

### Persistence

`JsonStore` serializes access with a process semaphore and writes a temporary file before atomic replacement. This prevents partial state after a process interruption. It is suitable for one instance and modest scan history. PostgreSQL is the intended adapter for horizontal scaling.

### User interface

The dashboard is static HTML/CSS/JavaScript with no build toolchain. All untrusted values are HTML-escaped before rendering. It supports repository registration, manual scans, key metrics, policy state, and remediation display.

## Security model

- Trust boundary: repository content is hostile; repository path registration is administrative.
- No repository content is evaluated or executed.
- Repository mounts should be read-only.
- Limits bound file count and individual text-file size.
- Generated, dependency, binary, and build-output content is excluded.
- Docker runs with the non-root UID supplied by the official .NET image, drops all capabilities, forbids privilege escalation, and uses a read-only root filesystem.
- The application has no outbound-network requirement.

## Scaling path

For enterprise expansion, preserve the API/domain model and replace infrastructure in this order:

1. PostgreSQL persistence with organization identifiers and row-level isolation.
2. OIDC authentication and organization-scoped RBAC.
3. Queue-backed scan jobs with rootless ephemeral containers.
4. GitHub App installation tokens and verified webhooks.
5. External adapters for Semgrep, Gitleaks, Trivy, Checkov, Syft, and Grype.
6. Object storage for artifacts and SBOMs.
7. OpenTelemetry traces, metrics, logs, and SLOs.

Do not run more than one API instance with the JSON store. The file lock is process-local, not distributed.
