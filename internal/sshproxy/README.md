# Iron SSH listener

SSH runs as an optional listener inside the main `iron-proxy` process. Build and
test it with the normal repository commands; no separate executable or module
is needed. The module uses sshpiper's crypto replacement for transport support.

Configure a top-level `ssh:` block in the regular YAML file, or set
`IRON_SSH_CONFIG_JSON` to the equivalent JSON object for managed deployments.
SSH is disabled when configuration is absent. Pass `--ssh` to require a configured
listener at startup. Listener settings apply at startup.

The SSH configuration contains `listen`, `host_key` (an existing Iron
secret source), `client_public_key` (registered by the trusted control plane),
`authorize_url`, and `token_env`. The environment variable named by `token_env`
is a proxy-only bearer token. Configuration and host keys must never be mounted
in the sandbox. `upstream_deny_cidrs` uses Iron's existing dial-time IP guard;
omission blocks loopback and cloud metadata. Explicit overrides are intended
for trusted operator configuration, including loopback-only integration tests.

The authorizer receives `{route, public_key}` and an optional `destination` for
per-call targets. A client names these using SSH username
`ee:<base64url-encoded-WSS-URL>`; the proxy decodes this to route `ee` and passes
the URL to the authorizer. This is only a request: the authorizer must enforce
deployment-owned host/path policy and must never infer a user from this input.
It must derive the principal from
the proxy token and return a grant containing `id`, `principal`, `generation`,
`destination` (`tcp://host:port` or a full `wss://host/path`), `username`,
`host_key` (authorized-key format), `private_key` (Iron secret source), and
`expires_at` (RFC3339, at most 15 minutes away). It must deny ambiguous or
unauthorized routes. Responses are limited to 1 MiB; errors never expose their
bodies or credential values. Redirects are not followed.

The paired public key is checked before authorization or any upstream dial.
Exec and SFTP channels are supported; forwarding is blocked. Global requests
are refused locally, and no-reply environment/end-of-write requests are discarded.
Other unsupported channel capabilities terminate the connection. Grants normally require a pinned SSH host key and verified WSS TLS.
An authorizer may explicitly return `tls_identity: true` with an empty
`host_key` for deployment-allowed WSS gateways. This authenticates the exact
destination using the TLS certificate and hostname, allowing the SSH key inside
that authenticated tunnel to rotate. It is rejected for plain TCP or combined
with a host pin. TLS verification, redirect rejection, IP guards, disposable
client keys, and per-request authorization remain mandatory. WSS implements
the wstunnel v11 default unmasked framing and routing handshake with a fixed remote target `127.0.0.1:22`.
The JWT is protocol metadata, not an authentication credential.

The lease is renewed every five seconds. Expiry, authorization failure, or a
change to any grant field except expiry closes the active connection. Authorizer
failures fail closed. Reconnection never retries a remote command automatically.
A terminated channel does not guarantee detached remote descendants have exited.

Run `go test -race ./internal/sshproxy`. No SSH functionality is enabled merely
by installing this binary; the embedding platform must supply the paired key,
authenticated authorizer, destination grants, and lifecycle wiring.
