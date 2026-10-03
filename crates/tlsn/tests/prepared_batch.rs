//! Real cryptography against local fixture certificates; no external accounts.

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
use tlsn_server_fixture::bind_with_keep_alive;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::TokioAsyncReadCompatExt;

const REQUEST: &[u8] =
    b"GET /bytes?size=17 HTTP/1.1\r\nHost: fixture\r\nConnection: keep-alive\r\n\r\n\
GET /bytes?size=29 HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n";

/// Completes fresh preprocessing before creating the provider transport, then
/// authenticates both HTTP responses under one TLS connection and one proof.
/// Run with RAYON_NUM_THREADS=32 and the tests-integration profile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real MPC cryptography; run explicitly with --ignored"]
async fn prepared_mpc_authenticates_two_pipelined_reads() {
    run_prepared_batch(512, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real MPC cryptography; run explicitly with --ignored"]
async fn exact_sent_allocation_authenticates_complete_batch() {
    // One application record, plus the two protocol records. The byte bound
    // covers the exact application request; MPC-TLS adds protocol byte space.
    run_prepared_batch(REQUEST.len(), 3).await;
}

async fn run_prepared_batch(max_sent_data: usize, max_sent_records: usize) {
    let mpc = MpcTlsConfig::builder()
        .max_sent_data(max_sent_data)
        // The current implementation uses explicit record bounds as totals,
        // including two protocol records. Leave room for two application writes.
        .max_sent_records(max_sent_records)
        .max_recv_data(2048)
        .max_recv_data_online(32)
        .max_recv_records_online(2)
        .defer_decryption_from_start(true)
        .build()
        .unwrap();
    let roots = RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    };
    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());
    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(roots.clone())
                .build()
                .unwrap(),
        )
        .unwrap();
    let (driver_p, handle_p) = session_p.split();
    let (driver_v, handle_v) = session_v.split();
    let driver_p = tokio::spawn(driver_p);
    let driver_v = tokio::spawn(driver_v);

    // Both sides finish single-use preprocessing while no provider connection
    // exists. These typestates are consumed by connect/run and cannot be cloned.
    let (prepared, accepted) = tokio::join!(prover.commit(mpc), async {
        let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap() else {
            panic!("expected MPC");
        };
        verifier.accept().await
    });
    let prepared = prepared.unwrap();
    let accepted = accepted.unwrap();

    // This delay represents waiting for a buyer job. It reuses no material from
    // a previous proof and contacts no provider before demand arrives.
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let (provider_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server = tokio::spawn(bind_with_keep_alive(server_socket.compat(), true));
    let request = REQUEST;

    let prover = async {
        let (mut connection, prover) = prepared
            .connect(
                TlsClientConfig::builder()
                    .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                    .root_store(roots)
                    .build()
                    .unwrap(),
                provider_socket.compat(),
            )
            .unwrap();
        let proof_task = tokio::spawn(prover.into_future());
        connection.write_all(request).await.unwrap();
        connection.flush().await.unwrap();
        let mut response = Vec::new();
        connection.read_to_end(&mut response).await.unwrap();
        connection.close().await.unwrap();
        let mut prover = proof_task.await.unwrap().unwrap();
        assert_eq!(prover.transcript().sent(), request);
        assert_eq!(prover.transcript().received(), response);
        assert_eq!(
            response
                .windows(b"HTTP/1.1 200 OK".len())
                .filter(|v| *v == b"HTTP/1.1 200 OK")
                .count(),
            2,
        );
        assert!(response.windows(17).any(|v| v == [b'B'; 17]));
        assert!(response.ends_with(&[b'B'; 29]));

        let mut config = ProveConfig::builder(prover.transcript());
        config.server_identity();
        config.reveal_sent(&(0..request.len())).unwrap();
        config.reveal_recv(&(0..response.len())).unwrap();
        prover.prove(&config.build().unwrap()).await.unwrap();
        prover.close().await.unwrap();
        response
    };
    let verifier = async {
        let verifier = accepted.run().await.unwrap();
        let (output, verifier) = verifier.verify().await.unwrap().accept().await.unwrap();
        verifier.close().await.unwrap();
        output
    };
    let (response, verified) = tokio::join!(prover, verifier);
    let verified = verified.transcript.unwrap();
    assert!(verified.is_complete());
    assert_eq!(verified.sent_unsafe(), request);
    assert_eq!(verified.received_unsafe(), response);
    server.await.unwrap().unwrap();
    handle_p.close();
    handle_v.close();
    driver_p.await.unwrap().unwrap();
    driver_v.await.unwrap().unwrap();
}
