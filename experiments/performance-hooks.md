# Performance experiment hooks

These hooks measure protocol phases without changing cryptographic operations
or protocol messages. The `tlsn` feature `experiment-telemetry` is disabled by
default. Enable it for a controlled experiment and install a tracing subscriber
that enables only the `tlsn::experiment` target at `info` level. Disable inherited
span fields in any formatter. Existing broad TLS or application debug logging can
include private material and is unnecessary for these measurements.

Each phase event has exactly these fields:

| Field | Meaning |
| --- | --- |
| `phase` | A fixed source-code label identifying the role and operation |
| `elapsed_us` | Monotonic elapsed microseconds, bounded to `u64` |
| `completed` | `true` on successful completion; `false` if an error or cancellation abandons the phase |

The labels cover prover/verifier MPC allocation and preprocessing, prover/verifier
Proxy allocation and preprocessing, prover commitment negotiation, prover
commitment finalization, and prover selective disclosure. Durations can overlap
across parties, so do not sum them as an end-to-end latency estimate. Events carry
no account identifier, server name, request, transcript, credentials, or error
text. Transport byte counts and job correlation belong in the experiment runner.

## Preparing a fresh MPC session before demand

`Prover<Initialized>::commit(MpcTlsConfig).await` returns
`Prover<CommitAccepted<Mpc>>` only after compatibility negotiation, allocation and
preprocessing complete. `Verifier<CommitStart<Mpc>>::accept().await` does the same
on the verifier. Both `SessionDriver` futures must keep running throughout.

No provider socket is needed by either call. A runner can hold those prepared
typestates until demand arrives, then create the provider connection and consume
the prover with `connect(TlsClientConfig, provider_socket)`. The typestates cannot
be cloned. Preparation is single use: discard cancelled, expired or disconnected
sessions and create fresh ones. Keep a bounded pool and measure its idle memory
and verifier occupancy. This moves work before demand; it does not remove its
bandwidth or CPU cost.

The fixture test creates the provider transport only after both preparation
futures finish and waits 25 ms to represent an idle prepared session. It then
proves both requests and responses through real MPC cryptography against local
fixture certificates. No insecure VM or external account is involved.

## Safe allocation experiments

The current implementation adds 32 bytes of protocol space to the configured
application byte limits. Explicit record counts are passed directly into the MPC
record layer. Although the core builder descriptions refer to application
records, explicit values currently include protocol records. Leave room for the
two protocol records as well as the application writes. For one observed
application record, the fixture succeeds with `max_sent_records(3)` and an exact
`max_sent_data(request.len())` bound.

`max_recv_data_online(32)` and `defer_decryption_from_start(true)` are the defaults.
Deferred receive decryption avoids online work for the application responses.
`NetworkSetting::Latency`, also the default, selects the PRF mode that reduces
bandwidth while adding round trips. `NetworkSetting::Bandwidth` favors fewer
round trips at a higher bandwidth cost. Measure these settings separately.

Byte or record bounds must cover the complete provider interaction, including
all requests in a batch and any online response parsing. Undersized bounds cause
the protocol to fail; do not retry provider work automatically after an ambiguous
failure.

## Multiple reads in one TLS connection

The TLS transport and transcript support multiple HTTP messages. The controlled
fixture enables HTTP/1.1 keep-alive, sends two known independent requests in one
write, closes on the second response and authenticates the complete combined
transcript. This proves transport feasibility. It does not prove that X accepts
pipelined requests or that Scarlett's application policy accepts a batch.

Sequential reads that wait for each response before sending the next request
require online receive decryption. That changes the allocation and bandwidth
cost. Pipelining known independent reads lets the runner keep deferred
decryption, subject to the provider's HTTP behavior. Application verification
must still bind each request, response, result and settlement exactly.

## Reproduce the fixture validation

The pinned dependency requires Rust 1.95.0. Rayon needs enough worker threads for
the protocol's parallel dependencies; the repository CI uses 32.

```sh
cargo +1.95.0 test --locked -p tlsn --lib --features experiment-telemetry
cargo +1.95.0 check --locked -p tlsn --no-default-features
RAYON_NUM_THREADS=32 cargo +1.95.0 test --locked -p tlsn \
  --features experiment-telemetry --profile tests-integration \
  --test prepared_batch -- --ignored
cargo +nightly fmt --all --check
```

The two prepared-batch cases cover a generous allocation and an exact request
byte allocation with three total sent records. These local fixture results are
separate from real provider latency, reliability and throughput measurements.
