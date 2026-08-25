# GitHub App setup

## Permissions and events

Create a GitHub App owned by the intended user or organization with:

- Repository contents: read-only
- Metadata: read-only
- Checks: read/write only when check reporting is added
- Subscribe to `push` and `pull_request`

Webhook URL: `https://<repoguard-host>/api/webhooks/github`.

## Configuration

Set these environment variables through a secret manager:

```text
GitHub__WebhookSecret=<random webhook secret>
GitHub__AppId=<numeric app id>
GitHub__PrivateKeyPem=<PEM private key, newlines preserved or encoded as \n>
```

Never commit them. The application signs a short-lived RS256 app JWT, exchanges it for an installation token and uses that token only while cloning the exact repository referenced by the verified event.

## Webhook protections

- HMAC-SHA256 verification using constant-time comparison
- 10 MB request-body limit
- `X-GitHub-Delivery` idempotency
- only `push` and `pull_request` payloads produce jobs
- bounded queue of 100 jobs with backpressure
- exact commit checkout, not an untrusted branch name
- installation tokens are never logged or persisted

## Private versus public repositories

Private repositories require App ID, private key and an installation ID in the payload. Public repository events can be processed without an installation token, although all webhooks still require the shared webhook secret.

## Operational endpoints

`GET /api/v2/webhook-jobs` exposes queued, running, completed and failed states. Protect this endpoint with the same access control as the dashboard because repository names and failure details are operational data.
