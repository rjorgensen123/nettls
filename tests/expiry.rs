// SPDX-License-Identifier: MIT OR Apache-2.0
//! A client stops at an expired or not yet valid certificate, says which, and
//! can be told to accept it anyway (0.11.0) — with real handshakes over
//! loopback, for both the pinned client and `Trust`.

use std::sync::Arc;

use nettls::generations::{Generation, Trust};
use nettls::pin::{Rejection, classify};
use nettls::{
    CertSource, Expiry, TlsMaterial, TransportPolicy, install_crypto_provider,
    pinned_client_config, pinned_client_config_with,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const DAY: i64 = 86_400;

/// A self-signed certificate valid from `not_before` to `not_after` seconds
/// from now. `SelfSignedParams` cannot make one outside its window, so rcgen
/// builds it and the PEM is loaded.
fn material(not_before: i64, not_after: i64) -> TlsMaterial {
    let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let t = time::OffsetDateTime::now_utc();
    p.not_before = t + time::Duration::seconds(not_before);
    p.not_after = t + time::Duration::seconds(not_after);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = p.self_signed(&key).unwrap();
    TlsMaterial::load(&CertSource::pem(cert.pem(), key.serialize_pem())).unwrap()
}

fn expired() -> TlsMaterial {
    material(-2 * DAY, -3600)
}

fn not_yet_valid() -> TlsMaterial {
    material(DAY, 2 * DAY)
}

/// One-shot server presenting `m`. Returns the port.
async fn serve(m: &TlsMaterial) -> u16 {
    let acceptor = TlsAcceptor::from(m.server_config().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await
            && let Ok(mut tls) = acceptor.accept(tcp).await
        {
            let _ = tls.write_all(b"ok").await;
            let _ = tls.shutdown().await;
        }
    });
    port
}

/// One handshake. The error is the `io::Error` tokio-rustls returns.
async fn connect(
    port: u16,
    config: Arc<nettls::rustls::ClientConfig>,
) -> Result<(), std::io::Error> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = nettls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = TlsConnector::from(config).connect(name, tcp).await?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await?;
    assert_eq!(buf, b"ok");
    Ok(())
}

#[tokio::test]
async fn pinned_client_refuses_an_expired_certificate_and_says_so() {
    install_crypto_provider();
    let m = expired();
    let port = serve(&m).await;
    let config = pinned_client_config(&m.fingerprint_sha256()).unwrap();
    let err = connect(port, config).await.unwrap_err();
    let Rejection::Expired { now, not_after } = classify(&err) else {
        panic!("not classified as expired: {err}");
    };
    assert_eq!(not_after, m.not_after().unwrap());
    assert!(now > not_after);
}

#[tokio::test]
async fn pinned_client_refuses_a_not_yet_valid_certificate_and_says_so() {
    install_crypto_provider();
    let m = not_yet_valid();
    let port = serve(&m).await;
    let config = pinned_client_config(&m.fingerprint_sha256()).unwrap();
    let err = connect(port, config).await.unwrap_err();
    let Rejection::NotYetValid { now, not_before } = classify(&err) else {
        panic!("not classified as not yet valid: {err}");
    };
    assert_eq!(not_before, m.not_before().unwrap());
    assert!(now < not_before);
}

#[tokio::test]
async fn expiry_ignore_lets_an_expired_certificate_through() {
    install_crypto_provider();
    let m = expired();
    let port = serve(&m).await;
    let config = pinned_client_config_with(
        &m.fingerprint_sha256(),
        &[],
        &TransportPolicy::default(),
        Expiry::Ignore,
    )
    .unwrap();
    connect(port, config).await.unwrap();
}

#[tokio::test]
async fn an_unknown_certificate_is_untrusted_whatever_its_dates() {
    install_crypto_provider();
    let m = expired();
    let port = serve(&m).await;
    let other = material(-3600, DAY);
    let config = pinned_client_config(&other.fingerprint_sha256()).unwrap();
    let err = connect(port, config).await.unwrap_err();
    assert_eq!(classify(&err), Rejection::Untrusted, "{err}");
}

#[tokio::test]
async fn trust_refuses_an_expired_certificate_unless_told_to_ignore_it() {
    install_crypto_provider();
    let m = expired();
    let trust = Trust::from_approval(Generation::from_der(m.cert_chain()[0].as_ref().to_vec()));

    let port = serve(&m).await;
    let err = connect(port, trust.client_config().unwrap())
        .await
        .unwrap_err();
    assert!(matches!(classify(&err), Rejection::Expired { .. }), "{err}");

    let port = serve(&m).await;
    let config = trust
        .client_config_with(&[], &TransportPolicy::default(), Expiry::Ignore)
        .unwrap();
    connect(port, config).await.unwrap();
}

#[test]
fn classify_reads_a_rustls_error_and_calls_the_rest_other() {
    use nettls::rustls::{CertificateError, Error};
    let e = Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);
    assert_eq!(classify(&e), Rejection::Untrusted);
    let e = std::io::Error::other("connection reset");
    assert_eq!(classify(&e), Rejection::Other);
}
