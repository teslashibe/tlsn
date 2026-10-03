//! Real MPC failure supervision against fixture certificates, without accounts.

use std::time::{Duration, Instant};

use futures::{AsyncReadExt, AsyncWriteExt};
use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::ServerName,
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::TokioAsyncReadCompatExt;

struct AbortTask(tokio::task::AbortHandle);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Debug)]
struct Outcome {
    verified: bool,
    reader_stalled_after_backend_error: bool,
    backend_error: Option<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real MPC allocation fault; run explicitly with --ignored"]
async fn receive_budget_failure_is_visible_before_waiting_for_reader() {
    let normal = probe(4096).await;
    assert!(normal.verified, "normal allocation must prove the fixture");
    let overflow = probe(512).await;
    assert!(!overflow.verified, "oversized transcript must not verify");
    assert!(
        overflow.backend_error.as_ref().is_some_and(
            |error| error.contains("attempted to receive more data than was configured")
        ),
        "backend must report its receive bound"
    );
    println!(
        "E2_ALLOCATION_READER reader_stalled={}",
        overflow.reader_stalled_after_backend_error
    );
}

async fn probe(max_recv: usize) -> Outcome {
    let started = Instant::now();
    let roots = RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    };
    let request = b"GET /bytes?size=1024 HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n";
    let (p, v) = tokio::io::duplex(2 << 23);
    let mut p = Session::new(p.compat());
    let mut v = Session::new(v.compat());
    let prover = p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(roots.clone())
                .build()
                .unwrap(),
        )
        .unwrap();
    let (pd, ph) = p.split();
    let (vd, vh) = v.split();
    let pd = tokio::spawn(pd);
    let vd = tokio::spawn(vd);
    let _pg = AbortTask(pd.abort_handle());
    let _vg = AbortTask(vd.abort_handle());
    let config = MpcTlsConfig::builder()
        .max_sent_data(request.len())
        .max_sent_records(3)
        .max_recv_data(max_recv)
        .max_recv_records_online(3)
        .build()
        .unwrap();
    let (prepared, accepted) = tokio::join!(prover.commit(config), async {
        let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap() else {
            panic!("expected MPC");
        };
        verifier.accept().await
    });
    let prepared = prepared.unwrap();
    let accepted = accepted.unwrap();
    let (provider, server) = tokio::io::duplex(2 << 16);
    let server = tokio::spawn(bind(server.compat()));
    let _sg = AbortTask(server.abort_handle());
    let verifier = tokio::spawn(async move {
        let verifier = accepted.run().await?;
        let (output, verifier) = verifier.verify().await?.accept().await?;
        verifier.close().await?;
        Ok::<_, tlsn::Error>(output)
    });
    let _vg = AbortTask(verifier.abort_handle());
    let (mut connection, backend) = prepared
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(roots)
                .build()
                .unwrap(),
            provider.compat(),
        )
        .unwrap();
    let mut backend = tokio::spawn(backend.into_future());
    let _bg = AbortTask(backend.abort_handle());
    connection.write_all(request).await.unwrap();
    connection.flush().await.unwrap();
    let mut response = Vec::new();
    let mut completed = None;
    let result = {
        let read = connection.read_to_end(&mut response);
        tokio::pin!(read);
        tokio::select! {
            read_result = &mut read => read_result,
            result = &mut backend => match result {
                Ok(Err(error)) => {
                    // The backend error must be supervised independently of
                    // the plaintext reader. Measure whether the reader wakes.
                    let stalled = tokio::time::timeout(Duration::from_millis(250),&mut read).await.is_err();
                    let outcome = Outcome { verified:false, reader_stalled_after_backend_error:stalled, backend_error:Some(error.to_string()) };
                    println!("E2_ALLOCATION_METRIC max_recv={max_recv} verified=false reader_stalled={stalled} elapsed_ms={} error={}",started.elapsed().as_millis(),outcome.backend_error.as_ref().unwrap());
                    ph.close(); vh.close();
                    return outcome;
                }
                Ok(Ok(prover)) => { completed=Some(prover); read.await }
                Err(_) => panic!("fixture backend task failed"),
            },
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("fixture reader and backend both timed out"),
        }
    };
    if result.is_err() {
        let error = tokio::time::timeout(Duration::from_secs(1), &mut backend)
            .await
            .unwrap()
            .unwrap()
            .err()
            .unwrap();
        ph.close();
        vh.close();
        let outcome = Outcome {
            verified: false,
            reader_stalled_after_backend_error: false,
            backend_error: Some(error.to_string()),
        };
        println!(
            "E2_ALLOCATION_METRIC max_recv={max_recv} verified=false reader_stalled=false elapsed_ms={} error={}",
            started.elapsed().as_millis(),
            outcome.backend_error.as_ref().unwrap()
        );
        return outcome;
    }
    connection.close().await.unwrap();
    let mut prover = match completed {
        Some(p) => p,
        None => match backend.await.unwrap() {
            Ok(p) => p,
            Err(error) => {
                // Some SDK versions wake the plaintext reader with EOF rather
                // than an error. That is still a failed proof, never success.
                ph.close();
                vh.close();
                println!(
                    "E2_ALLOCATION_METRIC max_recv={max_recv} verified=false reader_stalled=false elapsed_ms={} error={error}",
                    started.elapsed().as_millis()
                );
                return Outcome {
                    verified: false,
                    reader_stalled_after_backend_error: false,
                    backend_error: Some(error.to_string()),
                };
            }
        },
    };
    assert_eq!(prover.transcript().sent(), request);
    assert_eq!(prover.transcript().received(), response);
    let mut proof = ProveConfig::builder(prover.transcript());
    proof.server_identity();
    proof.reveal_sent(&(0..request.len())).unwrap();
    proof.reveal_recv(&(0..response.len())).unwrap();
    prover.prove(&proof.build().unwrap()).await.unwrap();
    prover.close().await.unwrap();
    let output = verifier.await.unwrap().unwrap();
    assert!(output.transcript.unwrap().is_complete());
    ph.close();
    vh.close();
    server.await.unwrap().unwrap();
    pd.await.unwrap().unwrap();
    vd.await.unwrap().unwrap();
    println!(
        "E2_ALLOCATION_METRIC max_recv={max_recv} verified=true reader_stalled=false elapsed_ms={}",
        started.elapsed().as_millis()
    );
    Outcome {
        verified: true,
        reader_stalled_after_backend_error: false,
        backend_error: None,
    }
}
