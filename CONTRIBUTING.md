# Contributing

## Development setup

Install .NET SDK 10, clone the repository, and run:

```bash
dotnet build tests/RepoGuard.Tests/RepoGuard.Tests.csproj
dotnet run --project tests/RepoGuard.Tests
dotnet run --project src/RepoGuard.Api
```

No NuGet packages are required. `NuGet.Config` clears external feeds to make builds reproducible and offline-capable.

## Change workflow

1. Open an issue explaining the outcome and security implications.
2. Create a focused branch.
3. Add tests for behavior and failure cases.
4. Run the Release build and full test harness.
5. Update the relevant docs and rule catalog.
6. Open a pull request with evidence of verification.

## Code standards

- Nullable reference analysis and warnings-as-errors remain enabled.
- Keep HTTP, domain, persistence, scanning, and presentation responsibilities separated.
- Do not execute repository content.
- Never include real credentials in fixtures.
- Bound all operations over untrusted repository content.
- Escape untrusted content at presentation boundaries.
- Use deterministic identifiers and UTC timestamps.

## Adding a scanner adapter

Convert native output to the `Finding` model and retain the original scanner rule identifier. Run external binaries with an argument-list API, never a shell command string. Apply time, CPU, memory, disk, process, and output-size limits. Record scanner version and errors without emitting secrets.

## Commit style

Use concise imperative subjects, optionally following Conventional Commits: `feat: add checkov adapter`, `fix: bound SARIF ingestion`, `docs: describe OIDC deployment`.
