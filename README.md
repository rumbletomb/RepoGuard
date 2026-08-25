# RepoGuard

RepoGuard is a self-hosted DevSecOps control plane that scans local source repositories, normalizes security findings, evaluates release policy, and exports results as SARIF. It ships with a responsive dashboard and has no database or cloud dependency.

![Status](https://img.shields.io/badge/status-production--ready-brightgreen) ![.NET](https://img.shields.io/badge/.NET-10-512bd4) ![License](https://img.shields.io/badge/license-MIT-blue)

## Why RepoGuard?

Security tools often emit incompatible formats and leave release decisions to manual interpretation. RepoGuard creates one finding model, stable fingerprints, a human-readable policy result, scan history, and a GitHub-compatible SARIF output. Its native rules work immediately; specialized tools such as Trivy, Semgrep, Gitleaks, and Checkov can be added as adapters without changing the API.

## Features

- Native SAST, secret, container, and configuration checks
- Local repository registration and repeatable scans
- Stable finding fingerprints for historical correlation
- Configurable severity and secret policy gates
- SARIF 2.1.0 and JSON output
- Persistent, atomic JSON storage
- Dashboard with repository, scan, risk, and policy views
- File count, file size, generated-directory, and binary safety controls
- Non-root, read-only, capability-free container deployment
- Dependency-free test harness and GitHub Actions CI

## Quick start

### Docker Compose

Requirements: Docker 24+ with Compose v2.

```bash
git clone https://github.com/rumbletomb/RepoGuard.git repoguard
cd repoguard
REPOSITORY_ROOT=/absolute/path/to/repos docker compose up --build
```

Open <http://localhost:8080>. Repositories are visible inside the container under `/repositories`; for example `/repositories/payments-api`.

On PowerShell:

```powershell
$env:REPOSITORY_ROOT = "C:\code"
docker compose up --build
```

### Run with .NET

Requirements: .NET SDK 10.

```bash
dotnet run --project src/RepoGuard.Api
```

The development server URL is printed by ASP.NET Core. Register any absolute repository path accessible to the process.

## First scan using the API

```bash
curl -X POST http://localhost:8080/api/repositories \
  -H 'content-type: application/json' \
  -d '{"name":"demo","path":"/repositories/demo"}'

curl -X POST http://localhost:8080/api/repositories/REPOSITORY_ID/scans \
  -H 'content-type: application/json' \
  -d '{"commit":"local"}'
```

The scan response contains findings and a policy result. A failed policy is a successful HTTP operation with `status: "failed"`; automation should inspect that value.

## Test and verify

```bash
dotnet build tests/RepoGuard.Tests/RepoGuard.Tests.csproj -c Release
dotnet run --project tests/RepoGuard.Tests -c Release --no-build
```

The suite covers finding detection, directory exclusions, pass/fail policies, deterministic fingerprints, and SARIF output.

## Documentation

- [Architecture and design](docs/architecture.md)
- [REST API reference](docs/api.md)
- [Rule catalog](docs/rules.md)
- [Operations and deployment](docs/operations.md)
- [Development and contribution](CONTRIBUTING.md)
- [Security policy and boundaries](SECURITY.md)

## Repository layout

```text
src/RepoGuard.Api/       API, scanner, persistence, SARIF and web UI
tests/RepoGuard.Tests/   zero-dependency executable test suite
examples/vulnerable/     intentionally vulnerable scan fixture
docs/                    architecture, API, rules and operations
.github/workflows/       build, test and container CI
```

## Current scope

Version 1.0 scans repositories already available on the host or mounted read-only into the container. It is intended for internal, administrator-operated use. It does not clone untrusted remote repositories, execute repository code, or provide internet-facing authentication. Deploy behind an authenticated identity-aware proxy when used by a team; see the operations guide.

## License

MIT. See [LICENSE](LICENSE).

