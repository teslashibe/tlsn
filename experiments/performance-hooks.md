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

## Bounded preparation pool experiment

`crates/tlsn/tests/prepared_pool.rs` keeps a small pool entirely inside the test
harness. Each entry owns a fresh prover, verifier, live session drivers and a
capacity permit. Preparation fixes the verifier session, fixture trust roots and
allocation class (512 sent bytes, 2 KiB received bytes, three total sent records,
two online received records, deferred decryption). The provider connection and
the exact request are created after demand takes an entry.

The harness tests these behaviors with real cryptography:

- Two prepared entries wait for delayed demand and prove two different requests
  in a burst. A third take returns no capacity. Leased entries retain their
  capacity permits, so refill cannot exceed the limit of two entries or four
  driver tasks.
- Successful consumption releases capacity; refill creates new sessions with
  fresh material. The prepared typestates are moved once and are never cloned,
  serialized, restored or reused.
- Cancelling a ready entry or a leased entry before provider execution closes
  and joins both drivers. Expiry removes ready entries and is checked again at
  execution, so taking a lease cannot extend the material's TTL. Neither
  cancelled nor expired entries open a provider connection.
- Cancelling a pending negotiation, after the verifier receives the config but
  before acceptance, aborts owned drivers and releases its capacity permit. A
  new independent preparation then completes and proves a request.
- Every successful proof authenticates the complete fixture request and
  response, including a different public test job identifier in each request.

```sh
CARGO_BUILD_JOBS=2 RAYON_NUM_THREADS=32 cargo +1.95.0 test --locked -p tlsn \
  --features experiment-telemetry --profile tests-integration \
  --test prepared_pool -- --ignored --nocapture --test-threads=1
```

The runner emits sanitized `E3_METRIC` rows. `setup_us` runs from session creation
through successful fresh preprocessing on both parties. `idle_us` measures the
time from ready until demand, including time spent preparing other entries.
`online_us` runs from demand through provider transport creation, TLS exchange,
proof generation and successful verifier acceptance. It excludes pool cleanup
after verification. Preparation and execution still consume the full protocol
work; preparation moves some of it before demand.

This fixture pool is an SDK feasibility experiment. It does not authorize a
generic warm pool against Scarlett's deployed verifier. Preparation itself is
bound to a verifier session and allocation class; it is not bound to a funded
Scarlett job. A production implementation still needs explicit preparation
admission with bounded verifier resources, authenticated allocation and TTL limits, later
binding to the exact funded job before provider execution, cancellation and
expiry across both processes, accounting for capacity while entries are leased,
and restart cleanup. Provider accounts and request sizes must fit the admitted
class. Remote verifier latency, actual X bandwidth and sustained request
throughput require separate live measurements.

The [saved fixture measurements](prepared-pool-fixture-results.json) pin the test
source hash and contain every sanitized numeric row from the final validation:

| Phase | Samples | Minimum | Sample median | Maximum |
| --- | --- | --- | --- | --- |
| Fresh setup | 10 | 183.126 ms | 198.125 ms | 214.548 ms |
| Demand through verification | 4 | 68.206 ms | 89.299 ms | 111.079 ms |

The four successful requests include two concurrent requests in the bounded
burst and two independent recovery requests. This small mixed fixture sample
checks feasibility and cleanup; it does not establish live-provider latency
percentiles or sustainable throughput. No on-demand cold-path benchmark was run
by this harness, so adding setup and online times is only a phase accounting
comparison, not a measured latency improvement.

These measurements were rerun on the current alpha.16 fork. The earlier
[alpha.15 fixture measurements](prepared-pool-fixture-results-alpha15.json)
retain their original source pin. Both are small mixed correctness runs; they
do not establish a latency improvement between library versions.
