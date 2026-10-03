//! A fixture-only pool experiment. Every entry has fresh MPC material and its
//! own live verifier session, a fixed allocation class and fixture trust roots.
//! No Scarlett job authorization or production pool protocol is implemented.

use std::{
    collections::{HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use futures::{AsyncReadExt, AsyncWriteExt};
use tlsn::{
    Mpc, Session, SessionHandle,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::ServerName,
    prover::{Prover, state as prover_state},
    verifier::{Verifier, VerifierCommitStart, state as verifier_state},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinHandle,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

type Driver = JoinHandle<tlsn::Result<tokio_util::compat::Compat<tokio::io::DuplexStream>>>;

#[derive(Default)]
struct Resources {
    case: &'static str,
    active_drivers: AtomicUsize,
    peak_drivers: AtomicUsize,
    provider_connections: AtomicUsize,
}

struct DriverLifetime(Arc<Resources>);

struct AbortProofTask(tokio::task::AbortHandle);

impl Drop for AbortProofTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl DriverLifetime {
    fn new(resources: Arc<Resources>) -> Self {
        let count = resources.active_drivers.fetch_add(1, Ordering::SeqCst) + 1;
        resources.peak_drivers.fetch_max(count, Ordering::SeqCst);
        Self(resources)
    }
}

impl Drop for DriverLifetime {
    fn drop(&mut self) {
        self.0.active_drivers.fetch_sub(1, Ordering::SeqCst);
    }
}

struct LiveSession {
    prover_handle: SessionHandle,
    verifier_handle: SessionHandle,
    prover_driver: Option<Driver>,
    verifier_driver: Option<Driver>,
}

impl LiveSession {
    async fn close(mut self) {
        self.prover_handle.close();
        self.verifier_handle.close();
        let mut prover = self.prover_driver.take().unwrap();
        let mut verifier = self.verifier_driver.take().unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(&mut prover, &mut verifier)
        })
        .await;
        let Ok((prover_result, verifier_result)) = result else {
            prover.abort();
            verifier.abort();
            let _ = tokio::join!(prover, verifier);
            panic!("closing both session drivers must finish");
        };
        prover_result.unwrap().unwrap();
        verifier_result.unwrap().unwrap();
    }
}

impl Drop for LiveSession {
    fn drop(&mut self) {
        // A cancelled preparation future must not detach session drivers.
        self.prover_handle.close();
        self.verifier_handle.close();
        if let Some(driver) = &self.prover_driver {
            driver.abort();
        }
        if let Some(driver) = &self.verifier_driver {
            driver.abort();
        }
    }
}

struct NegotiationGate {
    reached: oneshot::Sender<()>,
    proceed: oneshot::Receiver<()>,
}

struct Prepared {
    id: usize,
    setup_us: u64,
    ready_at: Instant,
    expires_at: Option<Instant>,
    prover: Prover<prover_state::CommitAccepted<Mpc>>,
    verifier: Verifier<verifier_state::CommitAccepted<Mpc>>,
    session: LiveSession,
    permit: OwnedSemaphorePermit,
}

fn roots() -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    }
}

fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u64::MAX as u128) as u64
}

fn preparation_progress(case: &'static str, entry: usize, phase: &'static str, started: Instant) {
    println!(
        "E3_PROGRESS case={case} entry={entry} phase={phase} elapsed_us={}",
        micros(started.elapsed())
    );
}

fn unexpected_driver_exit(
    case: &'static str,
    entry: usize,
    role: &'static str,
    result: <Driver as std::future::Future>::Output,
) -> ! {
    let status = match result {
        Ok(Ok(_)) => "completed",
        Ok(Err(_)) => "sdk_error",
        Err(_) => "task_error",
    };
    println!("E3_DRIVER_EXIT case={case} entry={entry} role={role} status={status}");
    panic!("fixture session driver exited during preparation");
}

impl Prepared {
    async fn fresh(
        id: usize,
        permit: OwnedSemaphorePermit,
        resources: Arc<Resources>,
        gate: Option<NegotiationGate>,
    ) -> Self {
        let experiment_case = resources.case;
        let started = Instant::now();
        preparation_progress(experiment_case, id, "fresh_started", started);
        let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
        let mut session_p = Session::new(prover_socket.compat());
        let mut session_v = Session::new(verifier_socket.compat());
        let prover = session_p
            .new_prover(ProverConfig::builder().build().unwrap())
            .unwrap();
        let verifier = session_v
            .new_verifier(
                VerifierConfig::builder()
                    .root_store(roots())
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let (driver_p, handle_p) = session_p.split();
        let (driver_v, handle_v) = session_v.split();
        let lifetime_p = DriverLifetime::new(resources.clone());
        let lifetime_v = DriverLifetime::new(resources);
        let mut session = LiveSession {
            prover_handle: handle_p,
            verifier_handle: handle_v,
            prover_driver: Some(tokio::spawn(async move {
                let _lifetime = lifetime_p;
                driver_p.await
            })),
            verifier_driver: Some(tokio::spawn(async move {
                let _lifetime = lifetime_v;
                driver_v.await
            })),
        };
        let config = MpcTlsConfig::builder()
            .max_sent_data(512)
            .max_sent_records(3)
            .max_recv_data(2048)
            .max_recv_data_online(32)
            .max_recv_records_online(2)
            .defer_decryption_from_start(true)
            .build()
            .unwrap();
        preparation_progress(experiment_case, id, "drivers_started", started);
        let proving = async {
            preparation_progress(experiment_case, id, "prover_commit_started", started);
            let result = prover.commit(config).await;
            preparation_progress(experiment_case, id, "prover_commit_returned", started);
            result
        };
        let verifying = async {
            preparation_progress(experiment_case, id, "verifier_commit_started", started);
            let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap() else {
                panic!("expected MPC");
            };
            preparation_progress(experiment_case, id, "verifier_commit_received", started);
            // Cancellation test pauses after the verifier receives the request,
            // while the prover awaits acceptance and live drivers are running.
            if let Some(gate) = gate {
                gate.reached.send(()).unwrap();
                gate.proceed.await.unwrap();
            }
            let result = verifier.accept().await;
            preparation_progress(experiment_case, id, "verifier_accept_returned", started);
            result
        };
        let negotiation = async { tokio::join!(proving, verifying) };
        tokio::pin!(negotiation);
        let (prover, verifier) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                completed = &mut negotiation => completed,
                result = session.prover_driver.as_mut().unwrap() => {
                    unexpected_driver_exit(experiment_case, id, "prover", result)
                }
                result = session.verifier_driver.as_mut().unwrap() => {
                    unexpected_driver_exit(experiment_case, id, "verifier", result)
                }
            }
        })
        .await
        .expect("fixture preparation exceeded its ten-second liveness bound");
        let setup_us = micros(started.elapsed());
        println!("E3_METRIC case={experiment_case} kind=prepared entry={id} setup_us={setup_us}");
        Self {
            id,
            setup_us,
            ready_at: Instant::now(),
            expires_at: None,
            prover: prover.unwrap(),
            verifier: verifier.unwrap(),
            session,
            permit,
        }
    }

    async fn discard(self) {
        let Self {
            prover,
            verifier,
            session,
            permit,
            ..
        } = self;
        drop(prover);
        drop(verifier);
        session.close().await;
        drop(permit);
    }

    fn expired(&self) -> bool {
        self.expires_at
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    async fn serve(
        self,
        job: usize,
        size: usize,
        resources: Arc<Resources>,
    ) -> Option<Measurement> {
        // A lease does not extend the lifetime of its preprocessing material.
        if self.expired() {
            self.discard().await;
            return None;
        }
        let Self {
            id,
            setup_us,
            ready_at,
            prover,
            verifier,
            session,
            permit,
            ..
        } = self;
        let idle_us = micros(ready_at.elapsed());
        let started = Instant::now();
        resources
            .provider_connections
            .fetch_add(1, Ordering::SeqCst);
        // Provider transport is created only after demand consumes the entry.
        let (provider, server_socket) = tokio::io::duplex(2 << 16);
        let server = tokio::spawn(bind(server_socket.compat()));
        let _server_guard = AbortProofTask(server.abort_handle());
        let request = format!("GET /bytes?size={size}&experiment_job={job} HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n").into_bytes();
        let proving = async {
            let (mut connection, prover) = prover
                .connect(
                    TlsClientConfig::builder()
                        .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                        .root_store(roots())
                        .build()
                        .unwrap(),
                    provider.compat(),
                )
                .unwrap();
            let mut proof_task = tokio::spawn(prover.into_future());
            let _proof_guard = AbortProofTask(proof_task.abort_handle());
            let mut completed = None;
            let response_io = async {
                connection.write_all(&request).await.unwrap();
                connection.flush().await.unwrap();
                let mut response = Vec::new();
                connection.read_to_end(&mut response).await.unwrap();
                connection.close().await.unwrap();
                response
            };
            tokio::pin!(response_io);
            // A failed backend must not leave a fixture reader waiting forever.
            // Successful backend completion still drains buffered plaintext.
            let response = tokio::time::timeout(Duration::from_secs(10), async {
                tokio::select! {
                    response = &mut response_io => response,
                    backend = &mut proof_task => {
                        completed = Some(backend.expect("fixture backend task failed").expect("fixture TLS backend failed"));
                        response_io.await
                    }
                }
            }).await.expect("fixture response exceeded its ten-second liveness bound");
            let mut prover = match completed {
                Some(prover) => prover,
                None => tokio::time::timeout(Duration::from_secs(10), proof_task)
                    .await
                    .expect("fixture TLS finalization exceeded its liveness bound")
                    .expect("fixture backend task failed")
                    .expect("fixture TLS backend failed"),
            };
            assert_eq!(prover.transcript().sent(), request);
            assert_eq!(prover.transcript().received(), response);
            let mut config = ProveConfig::builder(prover.transcript());
            config.server_identity();
            config.reveal_sent(&(0..request.len())).unwrap();
            config.reveal_recv(&(0..response.len())).unwrap();
            prover.prove(&config.build().unwrap()).await.unwrap();
            prover.close().await.unwrap();
            response
        };
        let verifying = async {
            let verifier = verifier.run().await.unwrap();
            let (output, verifier) = verifier.verify().await.unwrap().accept().await.unwrap();
            verifier.close().await.unwrap();
            output
        };
        let (response, output) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(proving, verifying)
        })
        .await
        .expect("fixture proof exceeded its ten-second liveness bound");
        let verified = output.transcript.unwrap();
        assert!(verified.is_complete());
        assert_eq!(verified.sent_unsafe(), request);
        assert_eq!(verified.received_unsafe(), response);
        assert!(response.ends_with(&vec![b'B'; size]));
        let measurement = Measurement {
            entry: id,
            job,
            setup_us,
            idle_us,
            online_us: micros(started.elapsed()),
        };
        println!(
            "E3_METRIC case={} kind=verified entry={id} job={job} setup_us={setup_us} idle_us={idle_us} online_us={}",
            resources.case, measurement.online_us
        );
        server.await.unwrap().unwrap();
        session.close().await;
        drop(permit);
        Some(measurement)
    }
}

struct Measurement {
    entry: usize,
    job: usize,
    setup_us: u64,
    idle_us: u64,
    online_us: u64,
}

struct Pool {
    slots: Arc<Semaphore>,
    capacity: usize,
    ttl: Duration,
    next_id: usize,
    ready: VecDeque<Prepared>,
    resources: Arc<Resources>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real MPC cryptography; run explicitly with --ignored"]
async fn sustained_pool_refill_and_cold_sessions_conserve_capacity() {
    sustained_pool_comparison(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real MPC cryptography; run explicitly with --ignored"]
async fn sustained_parallel_pool_refill_and_cold_sessions_conserve_capacity() {
    sustained_pool_comparison(true).await;
}

async fn sustained_pool_comparison(parallel_refill: bool) {
    let prepared = Arc::new(Resources {
        case: if parallel_refill {
            "parallel_prepared"
        } else {
            "sustained_prepared"
        },
        ..Default::default()
    });
    let cold_resources = Arc::new(Resources {
        case: if parallel_refill {
            "parallel_cold"
        } else {
            "sustained_cold"
        },
        ..Default::default()
    });
    let mut pool = Pool::new(2, Duration::from_secs(5), prepared.clone());
    let cold_slots = Arc::new(Semaphore::new(2));
    let mut prepared_entries = HashSet::new();
    let mut cold_entries = HashSet::new();
    let campaign = Instant::now();
    for cycle in 0..15 {
        // Alternate cold/prepared block order. Both groups serve two jobs at
        // once; complete block clocks include every preparation and cleanup.
        for block in 0..2 {
            let started = Instant::now();
            let result = tokio::time::timeout(Duration::from_secs(20), async {
                if (cycle + block) % 2 == 0 {
                    let cold = |job| {
                        let resources = cold_resources.clone();
                        let permit = cold_slots.clone().try_acquire_owned().unwrap();
                        async move {
                            let started = Instant::now();
                            let label = resources.case;
                            let entry = Prepared::fresh(job, permit, resources.clone(), None).await;
                            let measured = entry.serve(job, 384, resources).await.unwrap();
                            println!(
                                "E3_JOB case={label} sequence={job} elapsed_us={}",
                                micros(started.elapsed())
                            );
                            measured
                        }
                    };
                    let (a, b) = tokio::join!(cold(cycle * 2 + 1), cold(cycle * 2 + 2));
                    (a, b, &cold_resources, &mut cold_entries)
                } else {
                    let filled = if parallel_refill {
                        pool.refill_parallel().await
                    } else {
                        pool.refill().await
                    };
                    assert_eq!(filled, 2);
                    assert_eq!(prepared.active_drivers.load(Ordering::SeqCst), 4);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let a = pool.take().await.unwrap();
                    let b = pool.take().await.unwrap();
                    assert!(pool.take().await.is_none());
                    assert_eq!(pool.refill().await, 0);
                    assert_eq!(pool.refill_parallel().await, 0);
                    let serve = |entry: Prepared, job| {
                        let resources = prepared.clone();
                        async move {
                            let started = Instant::now();
                            let label = resources.case;
                            let measured = entry.serve(job, 384, resources).await.unwrap();
                            println!(
                                "E3_JOB case={label} sequence={job} elapsed_us={}",
                                micros(started.elapsed())
                            );
                            measured
                        }
                    };
                    let (a, b) = tokio::join!(serve(a, cycle * 2 + 1), serve(b, cycle * 2 + 2));
                    (a, b, &prepared, &mut prepared_entries)
                }
            })
            .await;
            let (a, b, resources, entries) = match result {
                Ok(completed) => completed,
                Err(_) => {
                    let prepared_slots = pool.slots.clone();
                    pool.close().await;
                    let idle = tokio::time::timeout(Duration::from_secs(2), async {
                        while prepared.active_drivers.load(Ordering::SeqCst) != 0
                            || cold_resources.active_drivers.load(Ordering::SeqCst) != 0
                        {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .is_ok();
                    println!(
                        "E3_TIMEOUT parallel={} cycle={cycle} block={block} drivers_idle={idle} cold_permits={} prepared_permits={}",
                        parallel_refill,
                        cold_slots.available_permits(),
                        prepared_slots.available_permits(),
                    );
                    assert!(idle);
                    assert_eq!(cold_slots.available_permits(), 2);
                    assert_eq!(prepared_slots.available_permits(), 2);
                    panic!("fixture preparation/burst exceeded its twenty-second liveness bound");
                }
            };
            assert_eq!((a.job, b.job), (cycle * 2 + 1, cycle * 2 + 2));
            assert!(entries.insert(a.entry) && entries.insert(b.entry));
            assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 0);
            assert_eq!(
                resources.provider_connections.load(Ordering::SeqCst),
                (cycle + 1) * 2
            );
            assert_eq!(resources.peak_drivers.load(Ordering::SeqCst), 4);
            assert_eq!(cold_slots.available_permits(), 2);
            assert_eq!(pool.slots.available_permits(), 2);
            println!(
                "E3_BLOCK case={} cycle={cycle} jobs=2 elapsed_us={}",
                resources.case,
                micros(started.elapsed())
            );
        }
    }
    assert_eq!(prepared_entries.len(), 30);
    assert_eq!(cold_entries.len(), 30);
    pool.close().await;
    assert_eq!(prepared.active_drivers.load(Ordering::SeqCst), 0);
    println!(
        "{} jobs=60 elapsed_us={}",
        if parallel_refill {
            "E3_PARALLEL_CAMPAIGN"
        } else {
            "E3_CAMPAIGN"
        },
        micros(campaign.elapsed())
    );
}

impl Pool {
    fn new(capacity: usize, ttl: Duration, resources: Arc<Resources>) -> Self {
        assert!(capacity > 0);
        Self {
            slots: Arc::new(Semaphore::new(capacity)),
            capacity,
            ttl,
            next_id: 1,
            ready: VecDeque::new(),
            resources,
        }
    }

    async fn refill(&mut self) -> usize {
        let mut count = 0;
        while self.ready.len() < self.capacity {
            let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                break;
            };
            let id = self.next_id;
            self.next_id += 1;
            let mut entry = Prepared::fresh(id, permit, self.resources.clone(), None).await;
            entry.expires_at = Some(entry.ready_at + self.ttl);
            self.ready.push_back(entry);
            count += 1;
        }
        count
    }

    async fn refill_parallel(&mut self) -> usize {
        let mut preparations = Vec::new();
        while self.ready.len() + preparations.len() < self.capacity {
            let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                break;
            };
            let id = self.next_id;
            self.next_id += 1;
            preparations.push(Prepared::fresh(id, permit, self.resources.clone(), None));
        }
        // Every in-progress entry already owns a permit. Dropping this future
        // cancels owned preparation futures and closes their session drivers.
        let entries = futures::future::join_all(preparations).await;
        let count = entries.len();
        for mut entry in entries {
            entry.expires_at = Some(entry.ready_at + self.ttl);
            self.ready.push_back(entry);
        }
        count
    }

    async fn take(&mut self) -> Option<Prepared> {
        // Remove expired entries before issuing a lease. Refilling is explicit.
        while let Some(entry) = self.ready.pop_front() {
            if entry.expired() {
                entry.discard().await;
            } else {
                return Some(entry);
            }
        }
        None
    }

    async fn cancel(&mut self, id: usize) -> bool {
        let Some(index) = self.ready.iter().position(|entry| entry.id == id) else {
            return false;
        };
        self.ready.remove(index).unwrap().discard().await;
        true
    }

    async fn close(self) {
        for entry in self.ready {
            entry.discard().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real MPC cryptography; run explicitly with --ignored"]
async fn bounded_pool_consumes_fresh_entries_once_and_refills_after_burst() {
    let resources = Arc::new(Resources {
        case: "bounded_burst",
        ..Default::default()
    });
    let mut pool = Pool::new(2, Duration::from_secs(5), resources.clone());
    assert_eq!(pool.refill().await, 2);
    assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 4);
    assert_eq!(resources.provider_connections.load(Ordering::SeqCst), 0);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let a = pool.take().await.unwrap();
    let b = pool.take().await.unwrap();
    assert_ne!(a.id, b.id);
    assert!(pool.take().await.is_none());
    // Leased entries still occupy pool slots, preventing an unbounded refill.
    assert_eq!(pool.refill().await, 0);
    let (a, b) = tokio::join!(
        a.serve(101, 17, resources.clone()),
        b.serve(102, 29, resources.clone())
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!((a.job, b.job), (101, 102));
    assert_ne!(a.entry, b.entry);
    assert!(a.idle_us >= 50_000 && b.idle_us >= 50_000);
    assert!(a.setup_us > 0 && b.setup_us > 0 && a.online_us > 0 && b.online_us > 0);
    assert_eq!(pool.slots.available_permits(), 2);
    assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 0);
    // Refill creates new sessions and fresh MPC material, never the old entries.
    assert_eq!(pool.refill().await, 2);
    assert!(
        pool.ready
            .iter()
            .all(|entry| entry.id > a.entry.max(b.entry))
    );
    assert_eq!(resources.peak_drivers.load(Ordering::SeqCst), 4);
    pool.close().await;
    assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 0);
    assert_eq!(resources.provider_connections.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real MPC cryptography; run explicitly with --ignored"]
async fn expiry_and_cancellation_release_drivers_and_material_before_refill() {
    let resources = Arc::new(Resources {
        case: "expiry_cancel",
        ..Default::default()
    });
    let mut pool = Pool::new(1, Duration::from_millis(20), resources.clone());
    assert_eq!(pool.refill().await, 1);
    let cancelled = pool.ready.front().unwrap().id;
    assert!(pool.cancel(cancelled).await);
    assert!(!pool.cancel(cancelled).await);
    assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 0);
    assert_eq!(pool.slots.available_permits(), 1);
    assert_eq!(pool.refill().await, 1);
    let leased = pool.take().await.unwrap();
    let cancelled_lease = leased.id;
    assert_eq!(pool.refill().await, 0);
    leased.discard().await;
    assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 0);
    assert_eq!(pool.slots.available_permits(), 1);
    assert_eq!(pool.refill().await, 1);
    let expired_lease = pool.take().await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        expired_lease
            .serve(999, 11, resources.clone())
            .await
            .is_none()
    );
    assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 0);
    assert_eq!(resources.provider_connections.load(Ordering::SeqCst), 0);
    assert_eq!(pool.slots.available_permits(), 1);
    assert_eq!(pool.refill().await, 1);
    let expired = pool.ready.front().unwrap().id;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(pool.take().await.is_none());
    assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 0);
    assert_eq!(resources.provider_connections.load(Ordering::SeqCst), 0);
    pool.ttl = Duration::from_secs(5);
    assert_eq!(pool.refill().await, 1);
    let fresh = pool.take().await.unwrap();
    assert!(fresh.id > expired && fresh.id > cancelled && fresh.id > cancelled_lease);
    fresh.serve(201, 31, resources.clone()).await.unwrap();
    assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 0);
    assert_eq!(resources.provider_connections.load(Ordering::SeqCst), 1);
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real MPC cryptography; run explicitly with --ignored"]
async fn cancelling_pending_acceptance_releases_capacity_and_driver_tasks() {
    let resources = Arc::new(Resources {
        case: "pending_cancel",
        ..Default::default()
    });
    let slots = Arc::new(Semaphore::new(1));
    let (reached_tx, reached_rx) = oneshot::channel();
    let (_proceed_tx, proceed_rx) = oneshot::channel();
    let task = tokio::spawn(Prepared::fresh(
        1,
        slots.clone().try_acquire_owned().unwrap(),
        resources.clone(),
        Some(NegotiationGate {
            reached: reached_tx,
            proceed: proceed_rx,
        }),
    ));
    reached_rx.await.unwrap();
    assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 2);
    assert_eq!(slots.available_permits(), 0);
    task.abort();
    let Err(error) = task.await else {
        panic!("preparation must remain paused until cancelled");
    };
    assert!(error.is_cancelled());
    tokio::time::timeout(Duration::from_secs(2), async {
        while resources.active_drivers.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(slots.available_permits(), 1);
    assert_eq!(resources.provider_connections.load(Ordering::SeqCst), 0);
    let fresh = Prepared::fresh(
        2,
        slots.clone().try_acquire_owned().unwrap(),
        resources.clone(),
        None,
    )
    .await;
    fresh.serve(301, 37, resources.clone()).await.unwrap();
    assert_eq!(slots.available_permits(), 1);
    assert_eq!(resources.active_drivers.load(Ordering::SeqCst), 0);
}
