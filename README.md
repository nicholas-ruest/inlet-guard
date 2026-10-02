# inlet-guard

`inlet-guard` is a Rust library and CLI for fail-closed checks at an agent
gateway's inbound boundary. It evaluates recorded HTTP or WebSocket request
envelopes before dispatch and catches:

- DNS-rebinding and Host-header confusion with an exact canonical authority allowlist;
- cross-origin browser requests and malformed or opaque origins;
- HTTP body and WebSocket message size overruns using observed byte counts; and
- missing, expired, replayed, cross-run, cross-tool, or argument-substituted approvals for side-effecting tool calls.

The project is intentionally small and deterministic. It does not run a proxy,
terminate TLS, authenticate users, or execute tools. Integrate the library in a
gateway or feed it request envelopes from an admission hook.

## Install

Requires stable Rust 1.85 or newer.

```console
cargo install --path .
```

## Use

Evaluate one envelope. Exit `0` means allow, `2` means policy denial, and `1`
means invalid input or an operational error.

```console
cargo run -- check \
  --policy examples/policy.json \
  --request examples/allowed-request.json
```

Expected result:

```text
ALLOW request-42 (local-agent-gateway-v1)
```

A deliberately rebound, cross-origin, oversized, argument-substituted request
is denied:

```console
cargo run -- check \
  --policy examples/policy.json \
  --request examples/denied-request.json \
  --output json
```

Batch mode accepts JSONL from a file or standard input and returns `2` if any
request is denied:

```console
cargo run -- batch --policy examples/policy.json --input requests.jsonl
```

Approvals bind the exact canonical JSON arguments. Generate the digest before
an approver signs or stores the approval:

```console
cargo run -- digest-args --arguments arguments.json
```

Canonicalization recursively sorts object keys, preserves array order, removes
insignificant whitespace, and hashes the resulting UTF-8 JSON with SHA-256.

## Policy model

See [`examples/policy.json`](examples/policy.json). Host and Origin checks are
exact after normalization: DNS suffix wildcards are intentionally unsupported.
Side-effect approvals bind `request_id`, `run_id`, tool name, arguments digest,
issue time, and expiry. Request time is explicit in the envelope so checks are
reproducible and can be tested without wall-clock dependence.

Unknown JSON fields are rejected throughout. The crate forbids `unsafe` Rust.

## Verify

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo package --locked
cargo audit
```

CI repeats the format, Clippy, test, and package gates on every push and pull
request.

## Limitations

- `inlet-guard` validates metadata supplied by a trusted adapter. The adapter must count actual decoded bytes and must not trust a client-provided length alone.
- Exact Host/Origin allowlists do not replace TLS, authentication, authorization, CSRF protections, proxy trust configuration, or network isolation.
- The canonical JSON format is project-specific, not RFC 8785/JCS. Producers must use this crate or reproduce its documented key-sorting behavior exactly.
- Approval records are binding inputs, not signatures. Store them in an authenticated system or add a signature/MAC appropriate to your trust model.
- Explicit request timestamps make replay testing deterministic; a live gateway must set them from its trusted clock and separately enforce nonce consumption.

## License

MIT
