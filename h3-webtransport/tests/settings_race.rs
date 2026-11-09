//! A WebTransport CONNECT can overtake the client's control stream (and so its SETTINGS).
//! The server must wait for the SETTINGS instead of rejecting the session with
//! `H3_SETTINGS_ERROR` (draft-ietf-webtrans-http3 section 3.1).

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use h3_quinn::quinn::{self, crypto::rustls::QuicClientConfig, crypto::rustls::QuicServerConfig};
use h3_webtransport::server::WebTransportSession;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// HTTP/3 request stream payload: a HEADERS frame holding an extended CONNECT
/// (`:protocol: webtransport`), QPACK-encoded with literals only (no dynamic table).
fn connect_frame() -> Vec<u8> {
    let mut block = vec![0x00, 0x00]; // required insert count 0, delta base 0
    block.push(0xCF); // :method CONNECT (static 15)
    block.push(0xD7); // :scheme https (static 23)
    block.push(0xC1); // :path / (static 1)
    block.extend([0x50, 9]); // :authority (static name 0), literal value
    block.extend(b"localhost");
    block.extend([0x27, 0x02]); // literal name, 9 bytes (3-bit prefix 7 + 2)
    block.extend(b":protocol");
    block.push(12);
    block.extend(b"webtransport");
    let mut frame = vec![0x01, block.len() as u8]; // HEADERS
    frame.extend(block);
    frame
}

/// Control stream: stream type 0x00 then a SETTINGS frame enabling extended CONNECT,
/// HTTP datagrams and WebTransport.
fn control_stream() -> Vec<u8> {
    let mut settings = vec![0x08, 1, 0x33, 1];
    settings.extend([0xAB, 0x60, 0x37, 0x42, 1]); // SETTINGS_ENABLE_WEBTRANSPORT = 1
    let mut out = vec![0x00, 0x04, settings.len() as u8];
    out.extend(settings);
    out
}

#[tokio::test]
async fn accept_waits_for_client_settings() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der: CertificateDer<'static> = cert.cert.into();
    let key = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut scfg = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .unwrap();
    scfg.alpn_protocols = vec![b"h3".to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(scfg).unwrap())),
        "[::1]:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();

    let (tx, mut rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut h3 = h3::server::builder()
            .enable_webtransport(true)
            .enable_extended_connect(true)
            .enable_datagram(true)
            .max_webtransport_sessions(1)
            .build(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let resolver = h3.accept().await.unwrap().unwrap();
        let (req, stream) = resolver.resolve_request().await.unwrap();
        let res = WebTransportSession::<_, Bytes>::accept(req, stream, h3)
            .await
            .map(|_| ());
        let _ = tx.send(res);
        // keep the endpoint alive until the client is done
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut ccfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ccfg.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client("[::]:0".parse().unwrap()).unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(ccfg).unwrap(),
    )));
    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();

    // The CONNECT goes first; the control stream (SETTINGS) is held back.
    let (mut req_tx, _req_rx) = conn.open_bi().await.unwrap();
    req_tx.write_all(&connect_frame()).await.unwrap();

    // The server must neither fail nor finish while SETTINGS are missing.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut rx)
            .await
            .is_err(),
        "accept resolved before the client's SETTINGS arrived"
    );

    let mut ctl = conn.open_uni().await.unwrap();
    ctl.write_all(&control_stream()).await.unwrap();

    let res = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("accept did not complete after SETTINGS")
        .unwrap();
    assert!(res.is_ok(), "accept failed: {res:?}");
}
