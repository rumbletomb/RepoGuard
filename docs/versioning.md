# Versioning and migration

RepoGuard follows Semantic Versioning and records user-visible changes in `CHANGELOG.md`.

## Available lines

- `v1.0.0` freezes the original deterministic engine.
- `v2.0.0` adds the multi-scanner engine while retaining original `/api` endpoints.

## Data migration

The JSON state schema is additive. Existing repositories, scans and policy load unchanged. New collections—v2 scans, advisories, rules and webhook jobs—default to empty, and the versioned scanner registry is seeded automatically. Back up `repoguard.json` before upgrading.

## Rollback

Stop v2, restore the pre-upgrade state backup and start the `v1.0.0` image/tag. Do not point v1 at state written by later major releases without restoring its matching backup.

## API compatibility

Original v1 routes remain available. New behavior is namespaced under `/api/v2`, except the GitHub webhook receiver at `/api/webhooks/github`. The dashboard intentionally uses the v2 scan route after upgrade.
