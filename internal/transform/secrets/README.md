# Secret sources

See the [shared secret-source configuration](../../../README.md#secrets) for
injection, replacement, TTL caching, and JSON extraction.

## Turnkey Managed Secrets

[Turnkey Managed Secrets](https://docs.turnkey.com/features/secrets) stores secrets and exports them, encrypted end to
end, when a policy allows it. Use `type: turnkey` with `organization_id` and
`secret_id`. The proxy reads its API private key from `TURNKEY_API_PRIVATE_KEY`,
or the environment variable named by `api_private_key_env`. Give that API identity
a policy scoped to exporting the intended secret. The SDK verifies the Signer
signature and organization and decrypts an export encrypted to a fresh recipient
key generated in the proxy. Optional `ttl`, `failure_ttl`, and `json_key` use the
same cache and extraction behavior as other sources.

```yaml
source:
  type: turnkey
  organization_id: "<organization-id>"
  secret_id: "<secret-id>"
  api_private_key_env: TURNKEY_API_PRIVATE_KEY
  ttl: 1m
```

### Approval and cache limits

Keep the API private key in the trusted proxy process, outside the workload.
Configure `require: true` on the inject or replace block to reject requests when
the secret is unavailable. Before the first successful export, a pending human
approval makes the secret unavailable. This source does not implement an approval
UI.

If an export needs approval, the source keeps that activity and its recipient
key in memory. Later fetches read the same activity; they do not submit a new
export. When the activity is approved, the next fetch decrypts the result. If the
activity is rejected, fails, or is not found, the next fetch submits a new export.
The error and log message include the activity ID, for example
`approval_required, activity <activity-id>`. A config reload or process restart
discards the pending activity; approve the activity that the new process reports.
The source checks the activity once per fetch, so a long `failure_ttl` makes
it slower to notice an approval.

After a successful export, refresh failures (including approval-required or denied
exports) continue serving the cached credential, potentially indefinitely. Thus
`require: true` does not reject requests on these refresh failures. `ttl` is a
refresh interval, not a hard expiry or revocation deadline; export approval is
not approval of each HTTP request. Do not use this cache as a per-request approval
or immediate-revocation boundary.

### Client lifecycle and requests

One client is shared by all Turnkey sources in the process with the same
organization and API-key environment variable name, including sources from other
transforms and config reloads. A successful initialization captures the signing
key until the process restarts. A config reload does not rotate an already
cached client. Failed initialization is retried after the source's failure
cache expires.

Each fetch has a 30-second overall deadline and an 8-second HTTP timeout, so all
three attempts fit in the deadline. The SDK
retries transport errors and HTTP 5xx responses at most twice (three attempts),
reusing the same serialized body, stamp, and export recipient key. Turnkey's
[activity submission idempotency](https://docs.turnkey.com/api-reference/activities/overview)
is based on the request body. The whole export operation is not retried within a
fetch. Redirects and HTTP 4xx responses are not retried. A later cache refresh is
a separate export with a fresh recipient key, unless an export is waiting for
approval.

Errors expose only fixed categories such as `approval_required`,
`authentication_failed`, `permission_denied`, `rate_limited`, `timeout`, and
`service_unavailable`. SDK messages, response bodies, and activity details are
not logged. Unclassified errors use `export_failed`.

### Testing

Run the following from the repository root.

For a credential-free test of the Turnkey source, real SDK signature verification
and decryption, JSON extraction, retries, and required-secret rejection, run:

```sh
go test -race ./internal/transform/secrets -run '^TestTurnkeySourceSDKExportThroughTransform$' -v
```

This uses signed synthetic exports from a local server and a test-only Signer key.
Production source configuration cannot override the API endpoint or Signer key.

For an opt-in test against the real Turnkey API, use a non-root identity scoped
to a disposable secret containing a JSON object with an `api_key` string. Set
`TURNKEY_API_PRIVATE_KEY` in the test process environment and provide:

- `TURNKEY_INTEGRATION_ORGANIZATION_ID`: the secret's organization.
- `TURNKEY_INTEGRATION_SECRET_ID`: the disposable secret's ID.
- `TURNKEY_INTEGRATION_EXPECTED_FILE`: a local file containing the exact
  `api_key` bytes, without a trailing newline. Keep this file private.

```sh
go build -o iron-proxy ./cmd/iron-proxy
./iron-proxy generate-ca -outdir tmp
go test -race ./integration_test -integration -run '^TestTurnkeyManagedSecret$' -count=1
```

The test starts the built CLI and a loopback HTTP verifier. The verifier returns
only an authentication result; it does not echo the credential. The test covers
live export/decryption, JSON extraction, credential replacement, and rejection
of missing or alternative placeholders. It skips when the inputs are absent.
This test does not establish TLS transport behavior.

### Proxy transport limits

The source inherits the proxy's shared request matching behavior. Rules select
where to inject a credential; unmatched requests still follow the rest of the
proxy pipeline. Matching a host does not require TLS: a matching plaintext HTTP
request can receive the credential. A deployment that needs encrypted transport
must enforce that requirement separately.
Upstream [#306](https://github.com/paradigmxyz/iron-proxy/pull/306)
proposes TLS-only matching for credential injectors.

In the current proxy, a host-only `require: true` rule also rejects the synthetic
CONNECT preflight before the inner HTTPS request can present its placeholder.
Scope the secret rule to the intended HTTP methods and paths when using the
CONNECT listener. Upstream [#302](https://github.com/paradigmxyz/iron-proxy/pull/302)
addresses the shared preflight behavior.
