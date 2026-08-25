# Security policy

## Supported versions

Only the latest release on `main` receives security fixes.

## Reporting a vulnerability

Do not open a public issue. Use GitHub private vulnerability reporting or contact the repository owner privately. Include the affected version, impact, reproduction steps, and suggested mitigation. Expect acknowledgement within three business days.

## Security boundaries

RepoGuard reads repository files but never executes their contents. The native scanner enforces file-count and file-size limits and ignores generated/vendor directories. Container deployments run as a non-root user with all Linux capabilities removed, a read-only filesystem, and repository mounts read-only.

This community version is designed for trusted administrators on a private network. Before exposing it publicly, place it behind an authenticated reverse proxy and configure network access controls. Repository paths are administrator-level input.
