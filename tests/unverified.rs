// SPDX-License-Identifier: MIT OR Apache-2.0
//! The enrollment client (0.11.0): it reads any server's certificate, whatever
//! its dates, but only from a server that holds the key for it — with real
//! handshakes over loopback.

use std::sync::Arc;

use nettls::rustls;
use nettls::{
    CertSource, SelfSignedParams, TlsMaterial, cert_fingerprint_sha256, install_crypto_provider,
    unverified_client_config,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn fresh(name: &str) -> TlsMaterial {
    TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
        name,
        ["localhost"],
    )))
    .unwrap()
}

/// Expired an hour ago, built with rcgen and loaded as PEM.
fn expired() -> TlsMaterial {
    let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let t = time::OffsetDateTime::now_utc();
    p.not_before = t - time::Duration::days(2);
    p.not_after = t - time::Duration::hours(1);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = p.self_signed(&key).unwrap();
    TlsMaterial::load(&CertSource::pem(cert.pem(), key.serialize_pem())).unwrap()
}

/// A server showing `cert`'s certificate while signing with `key`'s key —
/// someone who copied a certificate without its key.
fn copied_certificate(cert: &TlsMaterial, key: &TlsMaterial) -> Arc<rustls::ServerConfig> {
    #[derive(Debug)]
    struct Fixed(Arc<rustls::sign::CertifiedKey>);
    impl rustls::server::ResolvesServerCert for Fixed {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    let provider = nettls::provider();
    let key_der = key
        .anchor_pkcs8()
        .unwrap()
        .expose(|k| rustls::pki_types::PrivateKeyDer::Pkcs8(k.to_vec().into()));
    let signer = provider.key_provider.load_private_key(key_der).unwrap();
    // `CertifiedKey::new` does not check that key and certificate match.
    let ck = rustls::sign::CertifiedKey::new(vec![cert.cert_chain()[0].clone()], signer);
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(Arc::new(ck)))),
    )
}

/// One-shot server. Returns the port.
async fn serve(config: Arc<rustls::ServerConfig>) -> u16 {
    let acceptor = TlsAcceptor::from(config);
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

/// One handshake with the enrollment client. Returns the fingerprint of the
/// certificate the server showed.
async fn look(port: u16) -> Result<String, String> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = TlsConnector::from(unverified_client_config().unwrap())
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let cert = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(cert_fingerprint_sha256(&cert))
}

#[tokio::test]
async fn it_reads_the_certificate_of_a_peer_nobody_pinned() {
    install_crypto_provider();
    let m = fresh("new peer");
    let port = serve(m.server_config().unwrap()).await;
    assert_eq!(look(port).await.unwrap(), m.fingerprint_sha256());
}

#[tokio::test]
async fn it_reads_an_expired_certificate_too() {
    install_crypto_provider();
    let m = expired();
    let port = serve(m.server_config().unwrap()).await;
    assert_eq!(look(port).await.unwrap(), m.fingerprint_sha256());
}

#[tokio::test]
async fn a_server_without_the_key_does_not_get_through() {
    install_crypto_provider();
    let (shown, signing) = (fresh("shown"), fresh("signing"));
    let port = serve(copied_certificate(&shown, &signing)).await;
    let err = look(port).await.unwrap_err();
    assert!(err.contains("BadSignature"), "{err}");
}
