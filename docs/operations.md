# Operations and deployment

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `REPOGUARD_DATA` | `data/repoguard.json` | Absolute or working-directory-relative state file |
| `ASPNETCORE_URLS` | framework default | Listen URL; container sets `http://+:8080` |
| `REPOSITORY_ROOT` | `./examples` in Compose interpolation | Host directory mounted read-only at `/repositories` |

## Storage and backup

The only mutable asset is the state JSON at `REPOGUARD_DATA`. Stop the process or snapshot the volume consistently, then copy this file. Restore by replacing it before start. Keep backups encrypted because paths and security findings may reveal sensitive system information.

## Production deployment

1. Build and scan the container in CI.
2. Mount repositories read-only and the data directory read-write.
3. Keep the root filesystem read-only and preserve the supplied security options.
4. Put TLS and authentication in an identity-aware reverse proxy.
5. Restrict access to administrators and CI service identities.
6. Block public ingress to the application port.
7. Collect process logs without repository source or credential values.
8. Back up state and test restoration.

Example reverse-proxy topology:

```text
corporate identity -> TLS reverse proxy -> RepoGuard:8080
                                             |
                                             +-> persistent data volume
                                             +-> read-only repository mount
```

## Health monitoring

Poll `GET /api/health`. A successful response confirms the process can serve requests; it does not scan storage. Monitor HTTP 5xx rate, scan duration, state volume capacity, and repeated policy failure separately.

## Container hardening

The Compose definition and Dockerfile implement:

- non-root UID 10001
- read-only root filesystem
- writable named data volume only
- temporary in-memory `/tmp`
- no added Linux capabilities
- `no-new-privileges`
- read-only repository mount

If external scanner adapters are added, run them in separate rootless ephemeral containers with CPU, memory, disk, process, time, and network limits. Never execute scanner processes in the API container using arguments supplied directly by a repository.

## Troubleshooting

### Repository not found

When running in Docker, use the container path `/repositories/...`, not the host path. Verify `REPOSITORY_ROOT` points to the parent host directory before `docker compose up`.

### State cannot be written

Ensure the directory containing `REPOGUARD_DATA` exists and is writable by the application identity. In the supplied image, `/data` belongs to UID 10001.

### Scan rejects a large repository

The 20,000-file limit is defensive. Exclude generated assets from the mounted working tree or split the repository before changing the source limit. Reassess memory and latency before raising it.

### Policy unexpectedly fails

Retrieve the scan and inspect `policy.violations`, then compare open findings to `GET /api/policy`. Policy updates are not retroactive.

## Upgrade and rollback

Back up the state file, deploy the new immutable image, verify health and a representative scan, then retire the previous image. Rollback means restoring the previous image and, only if the data format changed, its matching backup. Version 1.0 uses an explicit, human-readable JSON schema.
