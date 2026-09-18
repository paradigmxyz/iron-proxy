# iron-proxy

[![Docs](https://img.shields.io/badge/docs-iron--proxy-blue)](https://docs.iron.sh)
[![Latest Release](https://img.shields.io/github/v/release/ironsh/iron-proxy)](https://github.com/ironsh/iron-proxy/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/ironsh/iron-proxy)](https://hub.docker.com/r/ironsh/iron-proxy)

## The problem

CI jobs, AI coding agents, and sandboxed containers can make arbitrary outbound
requests. A compromised dependency, a prompt injection, or a malicious build
step can exfiltrate secrets, phone home, or open a reverse shell. Most
teams have zero visibility into what's leaving their workloads, let alone any
way to stop it.

## What iron-proxy does

iron-proxy is a MITM egress proxy with a built-in DNS server that sits between
your untrusted workload and the internet. It enforces default-deny at the
network boundary, so the workload can only reach domains you explicitly allow.
Real secrets never enter the sandbox. Workloads use proxy tokens, and
iron-proxy swaps in real credentials at egress, meaning a compromised workload
can exfiltrate a token that's worthless outside the proxy.

Single binary. Single YAML config.

- **Default-deny egress.** Every outbound request is blocked unless the
  destination matches your allowlist. List your domains and CIDRs, everything
  else gets a 403.
- **Upstream IP deny list.** Even when a host is allowed, the proxy refuses
  to dial it if its resolved address falls inside a denied CIDR — closing
  the SSRF/DNS-rebinding gap where an allowlisted hostname points at IMDS
  or loopback. Cloud metadata endpoints (`169.254.169.254`,
  `fd00:ec2::254`, and `fd20:ce::254`) and loopback are denied by default;
  override via `proxy.upstream_deny_cidrs` or
  `IRON_PROXY_UPSTREAM_DENY_CIDRS`.
- **Boundary-level secret injection.** Workloads send proxy tokens; iron-proxy
  replaces them with real secrets before the request leaves. If the sandbox is
  compromised, the attacker gets tokens that are useless outside the proxy.
- **Per-request audit trail.** Every request logged as structured JSON with
  the full transform pipeline result: which secrets were swapped, which rules
  matched, what got blocked and why.
- **Streaming-aware.** WebSocket upgrades and Server-Sent Events are proxied
  natively. No special configuration for agent workloads that hold long-lived
  connections.
- **Explicit proxy support.** Optional tunnel listener for tools that natively
  support proxy configuration via `HTTP_PROXY`, `HTTPS_PROXY`, or SOCKS5
  settings.
- **PostgreSQL MITM proxy.** Optional listener that authenticates clients
  against proxy-managed credentials, injects `SET ROLE` on the upstream
  session, and rejects client attempts to mutate the role (`SET ROLE`,
  `set_config('role', ...)`, DO blocks, etc.) via a SQL AST walk. Pairs with
  PostgreSQL row-level security to give per-tenant data isolation when the
  application connects as a shared service-account user. **Requires
  PgBouncer (if used) to run in `pool_mode = session`** — transaction or
  statement pool modes silently rebind backends between queries and would
  defeat the policy. See [docs.iron.sh](https://docs.iron.sh) for details.

Built for CI pipelines, GitHub Actions, AI agents (Claude Code, Cursor,
Codex), and any environment where you run code you don't fully trust.

<div align="center">
    <strong>Blocked exfiltration + secret rewriting in action:</strong>
    <br/><br/>
    <a href="https://screen.studio/share/Gq2zqtrp" target="_blank">
        <img src="./images/intro.gif" width="75%" />
    </a>
</div>
 
## Installation
 
Docker images are available on [Docker Hub](https://hub.docker.com/r/ironsh/iron-proxy)
and pre-built binaries for Linux/macOS (amd64/arm64) are on
[GitHub Releases](https://github.com/ironsh/iron-proxy/releases).
 
Or build from source:
 
```bash
go build -o iron-proxy ./cmd/iron-proxy
```

## Quick start

```bash
cd examples/docker-compose
docker compose up
```

This starts iron-proxy and a demo client that fires five requests through the
proxy. Check the logs to see allowed, blocked, and secret-rewritten requests:

```bash
docker compose logs proxy
```

Every request produces a structured JSON audit entry:

```json
{
  "host": "httpbin.org",
  "method": "GET",
  "path": "/headers",
  "action": "allow",
  "status_code": 200,
  "duration_ms": 142,
  "request_transforms": [
    { "name": "allowlist", "action": "continue" },
    {
      "name": "secrets",
      "action": "continue",
      "annotations": { "swapped": [{ "secret": "OPENAI_API_KEY", "locations": ["header:Authorization"] }] }
    }
  ]
}
```

Rejected requests include a `rejected_by` field and log at WARN level. See
[Audit log format](#audit-log-format) for the full schema.

## Production usage

### 1. Generate a CA

iron-proxy terminates TLS by generating leaf certificates on the fly, signed by
a CA you provide. Client containers must trust this CA.

```bash
mkdir -p certs
openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -nodes \
    -key certs/ca.key \
    -sha256 -days 3650 \
    -subj "/CN=iron-proxy CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" \
    -out certs/ca.crt
```

### 2. Create a Docker network

iron-proxy needs a fixed IP so containers can point their DNS at it:

```bash
docker network create --subnet=172.20.0.0/24 iron-proxy
```

### 3. Start iron-proxy

Create an env file with your secrets (keep this out of version control):

```bash
echo "OPENAI_API_KEY=sk-real-key" > .env
```

```bash
docker run -d --name iron-proxy \
  --network iron-proxy --ip 172.20.0.2 \
  -v $(pwd)/proxy.yaml:/etc/iron-proxy/proxy.yaml:ro \
  -v $(pwd)/certs/ca.crt:/etc/iron-proxy/ca.crt:ro \
  -v $(pwd)/certs/ca.key:/etc/iron-proxy/ca.key:ro \
  --env-file .env \
  ironsh/iron-proxy:latest -config /etc/iron-proxy/proxy.yaml
```

### 4. Route containers through the proxy

The simplest approach is DNS-based routing: point the container's DNS at
iron-proxy and all hostname lookups resolve to the proxy IP, routing traffic
through it automatically:

```bash
docker run --rm \
  --network iron-proxy \
  --dns 172.20.0.2 \
  -v $(pwd)/certs/ca.crt:/certs/ca.crt:ro \
  curlimages/curl --cacert /certs/ca.crt https://httpbin.org/get
```

For stronger enforcement, layer nftables rules to block non-proxy egress, or use
TPROXY for kernel-level interception. See [Routing traffic to the
proxy](#routing-traffic-to-the-proxy) for details on each approach.

## Why iron-proxy?

|                          | iron-proxy                     | Squid                       | mitmproxy                 | Envoy                              |
| ------------------------ | ------------------------------ | --------------------------- | ------------------------- | ---------------------------------- |
| Default-deny egress      | Built-in                       | Requires complex ACL config | Requires custom scripting | Requires RBAC/filter configuration |
| Secret injection         | Built-in                       | No                          | No                        | No                                 |
| Structured audit logging | Built-in, per-transform traces | Basic access logs           | Plugin-based              | Configurable access logs           |
| Setup complexity         | Single binary + YAML           | Extensive config language   | Python scripting          | Complex YAML or control plane      |

iron-proxy is purpose-built for one job: controlling and auditing egress from
untrusted workloads. Squid can do default-deny but requires significant ACL
configuration and has no concept of secret injection. mitmproxy is a great
debugging tool but isn't designed for production enforcement. Envoy is a
general-purpose proxy that can be configured to do parts of this, but it's
far more complexity than the problem requires.

## How it works

iron-proxy runs a DNS server and an HTTP/HTTPS proxy. Point your container's DNS
at iron-proxy and all hostname lookups resolve to the proxy IP, routing traffic
through it automatically. The proxy terminates TLS (generating leaf certs on the
fly from a CA you provide), runs the request through an ordered transform
pipeline, forwards it upstream, and runs the response back through the pipeline.

```
Container → DNS lookup → iron-proxy IP → TLS termination → transforms → upstream
```

Transforms run in order. Built-in transforms:

| Transform   | What it does                                                                                                            |
| ----------- | ----------------------------------------------------------------------------------------------------------------------- |
| `allowlist`    | Permits requests to matching domains/CIDRs; rejects everything else (403).                                              |
| `secrets`      | Scans headers (and optionally query, path, or body) for proxy tokens and swaps in real secrets from environment variables. |
| `body_capture` | Records decoded request bodies of matching hosts as `request_body` audit fields, and optionally response bodies as `response_body`. Observation-only.        |

## Configuration

iron-proxy takes a single flag: `-config path/to/config.yaml`. Here's the
full shape (see [`iron-proxy.example.yaml`](iron-proxy.example.yaml) for a
copy-pasteable starting point):

```yaml
dns:
  listen: ":53"
  proxy_ip: "10.16.0.1" # IP where iron-proxy is running (required)
  passthrough: # Domains forwarded to OS resolver
    - "*.internal.corp"
    - "metadata.google.internal"
  records: # Static DNS records (highest precedence)
    - name: "internal.example.com"
      type: A
      value: "10.0.0.5"

proxy:
  http_listen: ":80"
  https_listen: ":443"
  tunnel_listen: ":8080" # Optional CONNECT/SOCKS5 listener
  max_request_body_bytes: 1048576 # 1 MiB (default)
  max_response_body_bytes: 0 # uncapped (default)

tls:
  ca_cert: "/etc/iron-proxy/ca.crt" # Required
  ca_key: "/etc/iron-proxy/ca.key" # Required
  cert_cache_size: 1000 # LRU cache for generated leaf certs
  leaf_cert_expiry_hours: 72

transforms:
  - name: allowlist
    config:
      domains:
        - "api.openai.com"
        - "*.anthropic.com"
      cidrs:
        - "10.0.0.0/8"

  - name: secrets
    config:
      secrets:
        - source:
            type: env
            var: OPENAI_API_KEY # Env var holding the real secret
          proxy_value: "proxy-token-123" # Token the sandbox sends
          match_headers: ["Authorization"]
          match_body: false
          require: true # Reject requests without the proxy token
          rules:
            - host: "api.openai.com"

log:
  level: "info" # debug, info, warn, error
```

### DNS

Everything resolves to `proxy_ip` by default, which is what routes traffic
through the proxy. Exceptions:

- **`passthrough`:** glob patterns forwarded to the OS resolver (e.g.,
  `*.internal.corp`). Traffic to these hosts bypasses the proxy entirely.
- **`records`:** static A or CNAME records. Highest precedence.

### Response retry handler

Set `IRON_RESPONSE_RETRY_HANDLER_URL`,
`IRON_RESPONSE_RETRY_COMPLETE_URL`, `IRON_RESPONSE_RETRY_HANDLER_TOKEN`,
`IRON_RESPONSE_RETRY_HANDLER_SANDBOX_ID`, and a comma-separated
`IRON_RESPONSE_RETRY_STATUSES` list to enable externally authorized response
retries. The authorization handler receives the exact upstream scheme, authority, method,
path/query, replayability, response status and headers, trace context, and
sandbox identity. It may return request headers plus an attempt ID for one
exact replay. The completion handler then receives the replay status and
response headers selected by `IRON_RESPONSE_RETRY_COMPLETION_HEADERS`, which
defaults to `Payment-Receipt`.

Response bodies are never sent to either handler, destinations cannot change,
and connection/framing headers are rejected. Requests over
`proxy.max_request_body_bytes` proceed normally but are marked non-replayable;
if challenged, their original response is returned. Handler failures also
preserve the original response. Handler URLs must use HTTPS unless loopback or
`IRON_RESPONSE_RETRY_HANDLER_ALLOW_HTTP=true` is explicitly configured for a
trusted internal network. Redirects are rejected, and the response retry token
must be configured independently from the control-plane token. WebSocket,
gRPC, and unknown-length streaming requests bypass response retry handling.

When a trusted handler resolves inside `proxy.upstream_deny_cidrs`, set
`IRON_RESPONSE_RETRY_HANDLER_ALLOW_CIDRS` to a comma-separated list of the
narrow private CIDRs it may use. This exception applies only to the exact
configured authorize and complete endpoints; ordinary proxied traffic remains
subject to the full upstream deny list. Public, loopback, link-local, and cloud
metadata ranges cannot be added through this setting.

### Allowlist

Default-deny. Requests must match at least one domain glob or CIDR to proceed.
Unmatched requests get a `403 Forbidden`.

Domain patterns use glob matching: `*.example.com` matches any subdomain and
`example.com` itself.

**Warn mode:** Set `warn: true` to observe what the allowlist would block without
actually enforcing it. Requests that would be rejected are allowed through but
annotated with `"action": "warn"` in the transform trace. This is useful for
rolling out new allowlist rules or auditing existing traffic before switching
to enforcement.

### Annotate

Captures HTTP request headers into audit log annotations based on
host/method/path rules. This is useful for enriching audit logs with
request-specific context like request IDs without modifying the proxy core.

Each annotation group specifies rules to match and headers to capture. When a
request matches any rule in a group, the specified header values are written as
`header:<Name>` entries in the transform trace annotations. Requests that don't
match are passed through unchanged. This transform never rejects requests.

> **Warning:** Header values are emitted in plain text in the audit log. Only
> log headers that are safe to expose, such as request IDs or headers containing
> proxy secret tokens. Do not log headers that contain raw secrets.

```yaml
transforms:
  - name: annotate
    config:
      annotations:
        - rules:
            - host: "api.openai.com"
              methods: ["POST"]
              paths: ["/v1/*"]
          headers: ["x-request-id"]
        - rules:
            - host: "*.anthropic.com"
          headers: ["x-request-id"]
```

### Header allowlist

Default-deny request header filter. Any request header whose canonical name is
not in the configured `headers` list is stripped before the request goes
upstream. Useful for blocking tracking, fingerprinting, or accidental leakage
headers (cookies, internal correlation IDs, `X-Forwarded-*`, etc.) that the
sandbox might attach.

Entries are matched case-insensitively against the canonical header name.
Patterns delimited by `/.../` (e.g. `/^X-Trace-.*$/`) are case-insensitive
regular expressions, mirroring the `secrets` transform's `match_headers`
syntax.

Optional `rules` limit the allowlist to specific hosts/methods/paths. When
omitted, the allowlist applies to every request that reaches this transform.

When at least one header is stripped, the trace is annotated with
`stripped_headers` listing the removed names.

> **Placement:** put `header_allowlist` *after* `secrets` (so injected
> credentials are not stripped if not in the allowlist, you can list them) and
> *after* `annotate` (so annotation reads the original headers).

```yaml
transforms:
  - name: header_allowlist
    config:
      headers:
        - "Authorization"
        - "Content-Type"
        - "User-Agent"
        - "Accept"
        - "/^X-Trace-.*$/"
      rules:
        - host: "api.openai.com"
```

### Body capture

Records the decoded request body of matching requests and surfaces it on the
audit log record in a `body_capture` group holding `request_body` and
`request_body_truncated`. Useful for auditing the payloads passing through the
proxy, such as the prompts a sandbox sends to an LLM provider, without
modifying the upstream traffic.

Hosts, methods, and paths are matched with the same `rules` syntax as
`allowlist` and `secrets`. `max_request_body_bytes` caps how much of each body
is captured; bodies larger than the cap are truncated to the prefix and
`request_body_truncated` is set to `true`. The cap defaults to 16 KiB and is
independent of the global `proxy.max_request_body_bytes` limit. This transform
is observation-only: it never rejects a request, and body read errors are
annotated on the trace rather than failing the request.

On a successful capture, the transform's entry in `request_transforms` is
annotated with `captured_bytes` and `truncated` so the trace records that a
body was captured without duplicating the body itself.

#### Response bodies

Response capture is **off by default**. Set `capture_response_body: true` to
turn it on; `response_body` and `response_body_truncated` then join the same
`body_capture` group, and `max_response_body_bytes` caps the copy (default
64 KiB).

The response half is *tee'd*, never buffered-then-forwarded. Installing the tee
is O(1) and never reads the body; the client's own reads drive the copy, so a
streaming reply (SSE from an LLM provider, say) is forwarded byte-for-byte as it
arrives and the audit copy simply holds whatever went past by the time the audit
record is emitted — which is after the body has been written to the client.
Bytes past `max_response_body_bytes` are *dropped* as they stream by rather than
queued, so a full audit buffer can never apply back-pressure to the client, and
a failing sink can never surface as a read error on the client's stream.

What lands in `response_body` is the raw reply as it went over the wire, only
content-decoded when the upstream compressed it (`gzip`, `deflate`; a reply in
an encoding the transform cannot decode is skipped and the gap is annotated on
the trace). SSE frames are not merged and JSON is not parsed — that is the log
consumer's job, and guessing at a provider's streaming shape does not belong on
the hot path.

> **Warning:** Captured bodies are written to the audit log in plain text, and
> that goes for captured response bodies too — enable `capture_response_body`
> only where an upstream's replies are safe to keep. When `secrets` runs with
> `match_body: true`, place `body_capture` *before* `secrets` so the audit log
> records the sandbox's proxy tokens rather than the real credentials `secrets`
> swaps into the body.

```yaml
transforms:
  - name: body_capture
    config:
      max_request_body_bytes: 16384
      # Optional; off by default.
      capture_response_body: true
      max_response_body_bytes: 65536
      rules:
        - host: "api.anthropic.com"
          methods: ["POST"]
          paths: ["/v1/messages"]
        - host: "api.openai.com"
          methods: ["POST"]
          paths: ["/v1/chat/completions"]
```

### Secrets

The sandbox never holds real credentials. Instead:

1. Configure iron-proxy with the real secret source: environment variables, a
   file on disk, AWS Secrets Manager, AWS Systems Manager Parameter Store,
   Vault KV, 1Password (service account), or 1Password Connect.
2. Give the sandbox a proxy token (e.g., `proxy-openai-abc123`).
3. Configure the `secrets` transform to map proxy tokens to those sources.

iron-proxy scans outbound requests and replaces proxy tokens with the real
values before forwarding upstream. You control where it looks:

- **`match_headers`:** list of header names to scan. Empty list = all headers.
  Literal names are matched case-insensitively, but the casing you write is
  preserved when the header is forwarded upstream. Entries delimited by `/.../`
  are compiled as case-insensitive regular expressions matched against canonical
  header names (e.g. `/^x-.*-key$/`).
- **`match_body`:** scan the request body (buffered up to `max_request_body_bytes`).
- **`match_query`:** scan the URL query string. Defaults to `false`; opt in for
  upstreams that expect the secret in a query parameter. Query strings often
  appear in access logs on either side of the proxy, so this is off by default.
- **`match_path`:** scan the URL path. Defaults to `false`; opt in for upstreams
  like Telegram that embed the secret in the path (e.g.
  `/bot<TOKEN>/sendMessage`). URL paths often appear in access logs on either
  side of the proxy, so this is off by default.
- **`require`:** when `true`, requests to a matching host that do **not** contain
  the proxy token are rejected with 403. This prevents a compromised workload
  from bypassing the secret-swap mechanism with alternative credentials. Default: `false`.
- **`hosts`:** restrict swapping to specific domains or CIDRs.

Query parameters are always scanned.

Secret sources:

- **`env`:** reads `var` from the proxy process environment. Fixed at process
  start — use `file` instead if you need to rotate the value on a running proxy.
- **`file`:** reads the secret from `path` on disk. The file is re-read on every
  config reload (boot and each `POST /v1/reload`) and, when `ttl` is set, on
  cache expiry — so you can rotate a running proxy's secret by rewriting the
  file (atomically: write-temp + rename) and reloading, without a restart. The
  value is the exact file contents (no trimming), so the writer controls
  trailing whitespace. Optional `ttl` and `failure_ttl` are supported.
- **`aws_sm`:** reads `secret_id` from AWS Secrets Manager. Optional `region`,
  `ttl`, and `failure_ttl` are supported.
- **`aws_ssm`:** reads `name` from AWS Systems Manager Parameter Store. Optional
  `region`, `with_decryption`, `ttl`, and `failure_ttl` are supported.
  `with_decryption` defaults to `true`, which is the expected setting for
  `SecureString` parameters.
- **`vault_kv`:** reads the secret map at `path` from the Vault KV engine mounted
  at `mount`. `kv_version` may be `1` or `2` and defaults to `2`. The map is
  returned as JSON; set `json_key` to select one top-level string field. The
  official Vault client reads its address, token, namespace, TLS, and proxy
  settings from standard `VAULT_*` environment variables such as `VAULT_ADDR`,
  `VAULT_TOKEN`, `VAULT_NAMESPACE`, and `VAULT_CACERT`. Optional `ttl` and
  `failure_ttl` are supported. This source handles static KV data only; dynamic
  secrets with renewable leases are not supported.
- **`1password`:** resolves `secret_ref` (an `op://vault/item/[section/]field`
  reference) using a 1Password service account token. The token is read from
  `OP_SERVICE_ACCOUNT_TOKEN`. Optional `ttl` and `failure_ttl` are supported.
- **`1password_connect`:** resolves the same `op://vault/item/[section/]field`
  `secret_ref` against a self-hosted 1Password Connect server. The server URL
  is read from `OP_CONNECT_HOST` and the API token from `OP_CONNECT_TOKEN`.
  Optional `ttl` and `failure_ttl` are supported.

Every source also accepts an optional `json_key`. When set, the resolved value
is parsed as a JSON object and the single top-level string field at that key is
extracted. Use it to pull one field out of a JSON secret.

`ttl` controls how long a successfully fetched value is cached before refresh
(empty caches forever). `failure_ttl` controls how long a fetch error is
cached before retrying; it defaults to 1m and is independent of `ttl`, so a
long success TTL does not delay recovery from a transient backend outage.

For example, to select `api_key` from a KV v2 secret stored at
`secret/services/openai`:

```yaml
source:
  type: vault_kv
  mount: secret
  path: services/openai
  json_key: api_key
  ttl: 5m
  failure_ttl: 15s
```

For production machine authentication, run Vault Agent or Vault Proxy with
auto-auth and point the Vault client environment at its local listener. This
keeps AppRole, Kubernetes, or cloud authentication and token renewal outside
iron-proxy.

  > **Note:** a bug in `onepassword-sdk-go` breaks builds with `CGO_ENABLED=0`,
  > so iron-proxy pins a [fork](https://github.com/ironsh/onepassword-sdk-go)
  > via a `replace` directive in `go.mod` until the fix lands upstream.

### Judge

The judge transform calls an LLM to produce an allow/deny decision for
requests that match its URL rules. Each entry under `transforms:` is an
independent judge instance with its own natural-language policy, LLM backend,
timeout, semaphore, and circuit breaker. Operators can deploy zero, one, or
many judges with different prompts scoped to different rules.

```yaml
- name: judge
  config:
    name: "github-write-guard"    # required; identifies the instance in audit logs
    fallback: "deny"              # deny (default) | skip. No "allow" fallback ships in v1.
    timeout: "8s"                 # per-call LLM timeout
    max_concurrent: 100           # semaphore capacity; additional calls wait
    circuit_breaker:
      consecutive_failures: 5
      cooldown: "10s"
    rules:                        # uses the same matcher as allowlist/secrets
      - host: "api.github.com"
        methods: ["POST", "PATCH", "DELETE", "PUT"]
    provider:
      type: "anthropic"           # "anthropic" or "openai"
      model: "claude-haiku-4-5-20251001"
      api_key_env: "ANTHROPIC_API_KEY"
      max_tokens: 256
    prompt: |
      Natural-language policy describing what is allowed for requests that
      match the rules above. Kept short and specific.
```

Invariants:

- The judge can only reject. It never approves a request the static allowlist
  would have denied. Static deny always wins.
- Non-matching requests are ignored: no LLM call, no audit annotations.
- On LLM error, timeout, circuit-breaker-open, or malformed model output, the
  configured `fallback` applies. `deny` blocks the request (the recommended
  default for production). `skip` defers to the rest of the pipeline; since
  iron-proxy is default-deny, unmatched requests are still blocked.

Pipeline ordering with the secrets transform:

- **Recommended:** place the judge **before** the secrets transform. The LLM
  provider sees proxy tokens, never the real credentials the workload has
  access to.
- Alternatively, placing the judge after secrets lets it evaluate the exact
  wire form that will egress, at the cost of sending real credentials to the
  LLM provider. Only choose this if your threat model accepts that trade.

Supported providers:

- **`anthropic`** (Messages API). Uses `api_key_env`, `model`, optional
  `base_url` and `max_tokens`.
- **`openai`** (Chat Completions API). Same fields as above; set
  `type: openai`, point `api_key_env` at the env var holding your OpenAI
  key, and pick a model like `gpt-5.4-nano`.

Audit output: every matched request adds structured fields under the transform
trace, including `judge.instance`, `judge.decision`, `judge.reason`,
`judge.duration_ms`, `judge.input_tokens`, `judge.output_tokens`,
`judge.fallback_applied` (when a fallback fires), and
`judge.circuit_breaker_tripped` (when the breaker is open).

Credits: thanks to Brex for their CrabTrap project (MIT-licensed), which
informed this design.

## MCP policy

iron-proxy can speak [MCP's Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports). When a request matches a configured MCP server, the proxy parses the JSON-RPC body, applies a default-deny tool allowlist, and filters `tools/list` responses so denied tools never reach the agent. SSE responses are filtered per event so long-lived MCP streams stay live.

This is a first-class proxy capability rather than a transform: MCP responses can be open-ended SSE streams carrying arbitrary server-initiated messages, which does not fit the request/response transform contract.

```yaml
mcp:
  # JSON-RPC error envelope returned to the agent on policy denial.
  # Defaults: code -32001, message "blocked by iron-proxy policy".
  error:
    code: -32001
    message: "blocked by iron-proxy policy"
  servers:
    - name: github                         # appears in audit as mcp.server
      rules:                               # standard host/method/path rules
        - host: "mcp.github.com"
          paths: ["/mcp", "/mcp/*"]
      tools:
        - name: "search_repositories"      # always allowed
        - name: "create_issue"
          when:                            # all clauses must hold; otherwise deny
            - path: "owner"                # dotted path against arguments
              equals: "ironsh"
            - path: "repo"
              in: ["iron-proxy", "tunis-v2"]
        # Anything not listed is denied (default-deny).
```

Behavior:

- **`tools/call` enforcement.** Calls to tools that are not in the server's `tools` list, or whose `arguments` fail any `when` clause, are rejected without reaching upstream. The proxy returns a JSON-RPC error response with the configured code and message and the request's original `id`, so the MCP client sees a normal protocol error rather than an HTTP failure.
- **`tools/list` filtering.** Responses to `tools/list` have any tool not on the allowlist removed before reaching the agent. Works for both `application/json` and `text/event-stream` responses; SSE filtering operates per event so heartbeats and other messages on the stream pass through untouched.
- **Argument matching.** Each `when` clause has a dotted `path` (e.g. `arguments.repo`, `labels.0`) and one of `equals` (any JSON scalar), `in` (a list of scalars), or `matches` (a regex on string values). Clauses AND together. Omitting `when` allows the tool unconditionally.
- **Audit.** Every observed JSON-RPC message is recorded under a new `mcp` section in the audit log entry: server name, direction (`request` or `response`), method, tool, decision (`allow`, `deny`, or `filtered`), reason on denials, and the count of tools removed on filter events.

Pipeline ordering: the MCP interceptor runs after the transform pipeline, so `allowlist` still gates which hosts can be reached and `secrets` has already swapped proxy tokens by the time the interceptor evaluates the body.

### MCP Gateway

`mcp_gateway` routes client-facing MCP hosts to concrete upstream servers after the MCP policy accepts the request. This lets agents call stable internal hosts while iron-proxy forwards to the real upstream and injects credentials that never enter the sandbox.

Gateway routes only apply to requests that matched an MCP server. The MCP policy still enforces the tool allowlist first. If policy denies a `tools/call`, the gateway route is not applied and upstream is not reached.

```yaml
mcp:
  servers:
    - name: github
      rules:
        - host: "github.mcp.local"
          paths: ["/mcp", "/mcp/*"]
      tools:
        - name: "search_repositories"

mcp_gateway:
  routes:
    - name: github
      rules:
        - host: "github.mcp.local"
          paths: ["/mcp", "/mcp/*"]
      upstream: "https://mcp.github.com/v1"
      credentials:
        - source:
            type: env
            var: GITHUB_MCP_TOKEN
          inject:
            header: Authorization
            formatter: "Bearer {{ .Value }}"
```

Credentials use the same secret sources as the `secrets` transform. They are required by default. Set `require: false` on a credential to skip it when unavailable. Audit logs record the route, upstream URL, and credential injection locations, but never the injected credential values.

Limitations in v1:

- Only Streamable HTTP transport is supported. The legacy HTTP+SSE transport (separate `/messages` and `/sse` endpoints) is not.
- A JSON-RPC batch with any denied entry is rejected as a whole batch; partial-batch forwarding is not supported.
- Resources and prompts are not enforced. Agents can still call `resources/list`, `resources/read`, etc. without policy filtering.

### Body limits

Transforms that inspect or forward request/response bodies (secrets body
matching, gRPC transforms) operate on buffered bodies. Two global settings
control the maximum buffer sizes:

- **`max_request_body_bytes`** (default: `1048576` / 1 MiB): caps how much of
  the request body is buffered for transforms. Data beyond this limit is
  truncated from the transform's perspective but still forwarded to upstream.
- **`max_response_body_bytes`** (default: `0` / uncapped): caps how much of
  the response body is buffered. Set to `0` to buffer the full response, which
  is the right default for most workloads (e.g., npm packages, model weights).

Bodies are buffered incrementally as transforms read them, and automatically
rewound between pipeline stages. If a transform doesn't read the body, no
buffering occurs and the body streams through untouched.

### Tunnel listener (HTTP/CONNECT/SOCKS5)

The tunnel listener accepts absolute-form HTTP proxy requests, HTTP CONNECT,
and SOCKS5 connections on a dedicated port. This is useful for tools that
natively support proxy configuration via `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`
environment variables or SOCKS5 settings, rather than relying on DNS-based
routing.

To enable it, set `tunnel_listen` under `proxy`:

```yaml
proxy:
  tunnel_listen: ":8080"
```

When omitted, the tunnel listener is disabled.

All protocols go through the same transform pipeline as regular HTTP/HTTPS
requests. Absolute-form HTTP requests are handled by the normal HTTP proxy
path. For CONNECT and SOCKS5, the proxy evaluates a synthetic CONNECT request
against your allowlist and secrets transforms, so tunnel connections are
subject to the same default-deny policy.

After the CONNECT or SOCKS5 handshake, the proxy peeks at the first byte to
detect the inner protocol:

- **TLS (0x16):** performs MITM the same way as the HTTPS listener,
  generating a leaf cert on the fly so transforms can inspect and rewrite
  the request.
- **Plain HTTP:** serves the request directly through the transform
  pipeline.

**HTTP CONNECT example:**

```bash
curl -x http://172.20.0.2:8080 \
  --cacert /certs/ca.crt \
  https://httpbin.org/get
```

**Plain HTTP proxy example:**

```bash
curl -x http://172.20.0.2:8080 \
  http://httpbin.org/get
```

**SOCKS5 example:**

```bash
curl --socks5-hostname 172.20.0.2:8080 \
  --cacert /certs/ca.crt \
  https://httpbin.org/get
```

You can also set the standard environment variables so all tools route
through the tunnel automatically:

```bash
export HTTP_PROXY=http://172.20.0.2:8080
export HTTPS_PROXY=http://172.20.0.2:8080
export ALL_PROXY=socks5h://172.20.0.2:8080
```

The SOCKS5 implementation supports no-auth only and accepts IPv4, IPv6,
and domain name address types.

### TLS

iron-proxy generates leaf certificates on the fly, signed by the CA you provide.
The client container must trust this CA (add it to the system trust store or pass
it via `--cacert`). Certs are cached in an LRU cache keyed by SNI hostname.

## Routing traffic to the proxy

There are three approaches, with increasing enforcement.

### DNS-based (simple)

Point the container's DNS at iron-proxy. All lookups resolve to the proxy IP,
so HTTP/HTTPS traffic flows through it naturally. This is what the
[Docker Compose example](#docker-compose-example) uses:

```yaml
services:
  client:
    dns:
      - 172.20.0.2 # iron-proxy IP
```

Easy to set up but easy to bypass: the workload can hardcode IPs or use its
own DNS resolver to skip the proxy entirely.

### DNS + nftables egress firewall (enforced)

Layer an nftables firewall on top of DNS routing. DNS still steers traffic to
the proxy, but nftables ensures the workload _can't_ talk to anything else,
even with hardcoded IPs.

The [`examples/nftables`](examples/nftables/) directory has a working setup.
The client container loads firewall rules on startup before running any
application traffic:

**nftables.conf** allows traffic to the proxy, drops everything else:

```
table ip iron {
  chain output {
    type filter hook output priority 0; policy drop;

    # allow loopback
    oif lo accept

    # allow traffic to the proxy itself (DNS + HTTP/HTTPS)
    ip daddr 172.20.0.2 tcp dport { 80, 443 } accept
    ip daddr 172.20.0.2 udp dport 53 accept

    # allow established/related (return traffic)
    ct state established,related accept

    # log and drop everything else
    log prefix "iron-proxy-drop: " drop
  }
}
```

**docker-compose.yml:** the client image is built with nftables
pre-installed. The entrypoint loads the rules, then runs the demo.
`CAP_NET_ADMIN` is required to load the rules:

```yaml
services:
  proxy:
    # ... same as DNS example ...
    networks:
      demo:
        ipv4_address: 172.20.0.2

  client:
    build:
      context: .
      dockerfile: Dockerfile.client # alpine + curl + nftables
    dns:
      - 172.20.0.2
    cap_add:
      - NET_ADMIN
    volumes:
      - ./nftables.conf:/etc/nftables.conf:ro
      - certs:/certs:ro
    networks:
      demo:
        ipv4_address: 172.20.0.4
```

In a production setup you'd load the rules in an entrypoint wrapper and then
`exec` your actual process as a non-root user without `CAP_NET_ADMIN`.

### TPROXY (transparent proxy)

For environments where you can't control the workload's DNS at all, nftables
TPROXY can redirect traffic at the kernel level without any cooperation from
the workload. This intercepts packets in the PREROUTING chain and hands them
directly to iron-proxy:

```
table ip iron {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;

    # redirect HTTP/HTTPS to iron-proxy via TPROXY
    tcp dport 80 tproxy to 172.20.0.2:80 meta mark set 1 accept
    tcp dport 443 tproxy to 172.20.0.2:443 meta mark set 1 accept
  }

  chain output {
    type route hook output priority mangle; policy accept;

    # mark locally-originated packets for policy routing
    tcp dport { 80, 443 } meta mark set 1
  }
}
```

This requires `ip rule` and `ip route` setup to route marked packets to a
local socket, plus iron-proxy must bind with `IP_TRANSPARENT`. This is more
complex to set up but provides the strongest guarantee that traffic can't
bypass the proxy. TPROXY operates below DNS, so it catches hardcoded IPs,
custom resolvers, and anything else the workload might try.

## Docker Compose example

The [`examples/docker-compose`](examples/docker-compose/) directory contains a
working setup. The key pieces:

**docker-compose.yml:** proxy and client on a shared bridge network. Real
secrets are set as env vars on the proxy container only:

```yaml
services:
  proxy:
    build:
      context: ../..
      dockerfile: examples/docker-compose/Dockerfile
    environment:
      - OPENAI_API_KEY=sk-real-openai-key-do-not-share
      - INTERNAL_TOKEN=real-internal-secret-value
    volumes:
      - certs:/certs
    networks:
      demo:
        ipv4_address: 172.20.0.2

  client:
    image: alpine:latest
    dns:
      - 172.20.0.2 # Point DNS at the proxy
    volumes:
      - certs:/certs:ro
    networks:
      demo:
        ipv4_address: 172.20.0.4
```

**proxy.yaml** allowlists `httpbin.org` and `icanhazip.com`, swaps two
secrets:

```yaml
transforms:
  - name: allowlist
    config:
      domains:
        - "httpbin.org"
        - "icanhazip.com"
      cidrs:
        - "172.20.0.0/24"

  - name: secrets
    config:
      secrets:
        - source:
            type: env
            var: OPENAI_API_KEY
          replace:
            proxy_value: "proxy-openai-abc123"
            match_headers: ["Authorization"]
            match_query: true # scan the query string
          rules:
            - host: "httpbin.org"

        - source:
            type: env
            var: INTERNAL_TOKEN
          proxy_value: "proxy-internal-tok"
          match_headers: [] # scan all headers
          rules:
            - host: "httpbin.org"
```

The client script sends five requests to demonstrate each behavior:

```bash
# 1. Allowed request
curl https://httpbin.org/get

# 2. Blocked request (not in allowlist)
curl https://example.com/

# 3. Secret swap: proxy token replaced with real key in Authorization header
curl -H "Authorization: Bearer proxy-openai-abc123" https://httpbin.org/headers

# 4. Secret swap: proxy token in custom header
curl -H "X-Internal: proxy-internal-tok" https://httpbin.org/headers

# 5. Secret swap: proxy token in query parameter
curl "https://httpbin.org/get?token=proxy-openai-abc123&q=hello"
```

## Audit log format

Every proxied request produces a structured JSON log entry:

```json
{
  "host": "httpbin.org",
  "method": "GET",
  "path": "/headers",
  "action": "allow",
  "status_code": 200,
  "duration_ms": 142,
  "request_transforms": [
    {
      "name": "allowlist",
      "action": "continue"
    },
    {
      "name": "secrets",
      "action": "continue",
      "annotations": {
        "swapped": [{ "secret": "OPENAI_API_KEY", "locations": ["header:Authorization"] }]
      }
    }
  ],
  "response_transforms": []
}
```

Rejected requests include a `rejected_by` field and log at WARN level.

## OpenTelemetry export

Audit events can be exported as OpenTelemetry structured log records for
offline analysis in backends like Axiom, ClickHouse, or Logfire. Set
`OTEL_EXPORTER_OTLP_ENDPOINT` to enable:

```bash
docker run -d --name iron-proxy \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=https://logfire-us.pydantic.dev \
  -e OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
  -e OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer <token>" \
  -e OTEL_SERVICE_NAME=iron-proxy \
  -e OTEL_RESOURCE_ATTRIBUTES="deployment.environment=staging" \
  # ... other flags ...
  ironsh/iron-proxy:latest -config /etc/iron-proxy/proxy.yaml
```

All configuration uses standard OTEL environment variables:

| Variable                       | Description                                             | Default          |
| ------------------------------ | ------------------------------------------------------- | ---------------- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector URL. OTEL export is disabled when unset. | (disabled)       |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` or `grpc`.                              | `http/protobuf`  |
| `OTEL_EXPORTER_OTLP_HEADERS`  | Comma-separated `key=value` pairs for auth headers.     | (none)           |
| `OTEL_SERVICE_NAME`            | Service name attached to all log records.                | `iron-proxy`     |
| `OTEL_RESOURCE_ATTRIBUTES`    | Comma-separated `key=value` resource attributes.        | (none)           |

When enabled, every audit event is emitted as an OTEL log record alongside the
existing JSON stderr logs. The log record carries the same schema as the JSON
audit entry: `host`, `method`, `path`, `action`, `status_code`, `duration_ms`,
and the full `request_transforms`/`response_transforms` arrays with annotations.

## Management API

iron-proxy can optionally expose an authenticated HTTP API for operational
tasks. Currently it serves a single endpoint, `POST /v1/reload`, which re-reads
the YAML config from disk and atomically swaps in a freshly built transform
pipeline. The running pipeline is preserved if the new config is invalid.

The management server is disabled by default. To enable, add a `management`
block to your config:

```yaml
management:
  # Bind on loopback unless you front this with a private network or auth proxy:
  # /v1/reload can rebuild the entire transform pipeline.
  listen: "127.0.0.1:9092"
  # Env var that holds the bearer token. Defaults to IRON_MANAGEMENT_API_KEY.
  api_key_env: "IRON_MANAGEMENT_API_KEY"
```

Standalone mode only — incompatible with control-plane managed mode.

Reload a running proxy:

```bash
curl -X POST http://127.0.0.1:9092/v1/reload \
  -H "Authorization: Bearer $IRON_MANAGEMENT_API_KEY"
```

## iron.sh

Need dynamic Vault secret engines, KMS backends, a Kubernetes operator, or
centralized policy management? [iron.sh](https://iron.sh) builds on iron-proxy
with enterprise features for teams running this at scale.

## Verify release signatures

Release artifacts include a signed checksum manifest:

- `checksums.txt`
- `checksums.txt.asc` (ASCII-armored detached signature)

Use the included public key at [`public-key.asc`](public-key.asc) to verify:

```bash
# 1) Download release artifacts for a tag
TAG=vX.Y.Z
gh release download "$TAG" --pattern "checksums.txt" --pattern "checksums.txt.asc"

# 2) Import the project signing key
gpg --import public-key.asc

# 3) Verify the signature over checksums.txt
gpg --verify checksums.txt.asc checksums.txt
```

If verification succeeds, GPG will report a good signature from `Matthew Slipper <matt@iron.sh>`.

You can optionally inspect the imported key fingerprint and confirm it matches your trusted source before verification.

To verify a specific binary against the signed checksum list (example: `iron-proxy-linux-amd64`):

```bash
shasum -a 256 iron-proxy-linux-amd64 | grep -F "$(grep -F 'iron-proxy-linux-amd64' checksums.txt | awk '{print $1}')"
```
