// SPDX-License-Identifier: MIT OR Apache-2.0
//! **M-6** — the §6 model against a live server that swaps certificates while
//! running.
//!
//! This is the test that was missing when phase 3.1 was wrongly ticked off as
//! done. The unit tests showed the state machine was correct; they could not
//! show it was *connected to anything*. Here the traffic runs over a real TCP
//! socket, with a real rustls handshake, and the server swaps certificates
//! between two connections.
//!
//! What the test actually has to prove:
//!
//! 1. An announced successor is accepted **without** the client being told
//!    when the swap happens (§6.7 — asynchronous rotation).
//! 2. `previous` is **not** accepted in a handshake after promotion, even
//!    though it is still used to verify announcements (§6.3, the two roles).
//! 3. A certificate that is neither `current` nor `next` is rejected
//!    (§6.8b).

use std::sync::Arc;

use nettls::announcement::{Announcement, Handled, Receipt};
use nettls::generations::{Generation, Trust};
use nettls::{CertSource, SelfSignedParams, TlsMaterial};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One generation: material, PEM, fingerprint and signing key.
struct Gen {
    material: TlsMaterial,
    pem: String,
    fp: String,
    pkcs8: krypto::SecretBuf,
}

impl Gen {
    /// A second locked copy of the key — `SecretBuf` is not `Clone` by design.
    fn key(&self) -> krypto::SecretBuf {
        self.pkcs8
            .expose(|b| krypto::SecretBuf::from_vec(b.to_vec()))
            .expect("mlock")
    }
}

fn generation() -> Gen {
    let material = TlsMaterial::load(&CertSource::self_signed(SelfSignedParams::new(
        "localhost",
        ["localhost"],
    )))
    .expect("self-signed");
    let der = material.cert_chain()[0].as_ref().to_vec();
    let pem = pem_of(&der);
    let fp = material.fingerprint_sha256();
    let pkcs8 = pkcs8_of(&material);
    Gen {
        material,
        pem,
        fp,
        pkcs8,
    }
}

fn pem_of(der: &[u8]) -> String {
    use std::fmt::Write;
    let b64 = base64_std(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        let _ = writeln!(s, "{}", std::str::from_utf8(line).unwrap());
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

fn base64_std(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for b in data.chunks(3) {
        let n = ((b[0] as u32) << 16)
            | ((*b.get(1).unwrap_or(&0) as u32) << 8)
            | (*b.get(2).unwrap_or(&0) as u32);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if b.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if b.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Extracts PKCS#8 from the material via `save_pem` + `load`, since the
/// internal conversion is not public.
fn pkcs8_of(m: &TlsMaterial) -> krypto::SecretBuf {
    let dir = std::env::temp_dir().join(format!(
        "nettls-m6-{}-{}",
        std::process::id(),
        m.fingerprint_sha256()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    m.save_pem(&dir).unwrap();
    let key_pem = std::fs::read_to_string(dir.join(nettls::KEY_FILE)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    use rustls_pki_types::pem::PemObject;
    let n = rustls_pki_types::PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes())
        .expect("pkcs8 key");
    krypto::SecretBuf::from_vec(n.secret_pkcs8_der().to_vec()).expect("mlock")
}

/// A server that presents exactly one certificate, and can be restarted with
/// a different one on the same port.
async fn server(port: u16, cfg: Arc<rustls::ServerConfig>) -> tokio::task::JoinHandle<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
    tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut s) = acceptor.accept(tcp).await {
                    let _ = s.write_all(b"hey").await;
                    let _ = s.shutdown().await;
                }
            });
        }
    })
}

/// One handshake. `Ok(())` means the client accepted the server's certificate.
async fn connect_to(trust: &Trust, port: u16) -> Result<(), String> {
    let cfg = trust.client_config().map_err(|e| e.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut s = connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 3];
    s.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    assert_eq!(&buf, b"hey");
    Ok(())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread")]
async fn announced_successor_accepted_without_client_knowing_when() {
    nettls::install_crypto_provider();

    let c0 = generation();
    let c1 = generation();
    let port = free_port();

    // The operator has approved c0.
    let trust = Trust::from_approval(
        Generation::from_der(c0.material.cert_chain()[0].as_ref().to_vec()).unwrap(),
    );

    // Server on c0. Sanity: the pin works NOW — without this the rest could
    // have "passed" against a dead server.
    let s0 = server(port, c0.cfg()).await;
    connect_to(&trust, port)
        .await
        .expect("cannot be assessed: c0 does not get through to begin with");

    // The announcement: c0 appoints c1. First rotation → single-signed (§6.3).
    let k = Announcement::new("gateway", None, (&c0.fp_bar(), &c0.pkcs8), &c1.pem, 1).unwrap();
    assert!(k.is_bootstrap(), "a first announcement has no previous");
    trust
        .receive(&k, "gateway")
        .expect("the announcement must be accepted");

    // The server swaps. The client has NOT been told when.
    s0.abort();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let s1 = server(port, c1.cfg()).await;

    connect_to(&trust, port)
        .await
        .expect("M-6 BROKEN: the announced successor was not accepted");

    // And the observation must have promoted the state (§6.7).
    let g = trust.state().unwrap();
    assert_eq!(
        g.current().fingerprint(),
        c1.fp_bar(),
        "promotion did not happen on observation"
    );
    assert_eq!(g.previous().unwrap().fingerprint(), c0.fp_bar());
    assert!(g.next().is_none());

    s1.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn previous_generation_does_not_get_in_after_promotion() {
    // The two roles (§6.3): `previous` verifies announcements, but must not
    // be usable for connecting. Mix them, and the window would become wider
    // than necessary — and the window's width is the whole reason a leaked
    // old key stops having value.
    nettls::install_crypto_provider();

    let c0 = generation();
    let c1 = generation();
    let port = free_port();

    let trust = Trust::from_approval(
        Generation::from_der(c0.material.cert_chain()[0].as_ref().to_vec()).unwrap(),
    );
    let k = Announcement::new("gateway", None, (&c0.fp_bar(), &c0.pkcs8), &c1.pem, 1).unwrap();
    trust.receive(&k, "gateway").unwrap();

    // Promote by actually seeing c1.
    let s1 = server(port, c1.cfg()).await;
    connect_to(&trust, port).await.expect("c1 must pass");
    s1.abort();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // We now stand at (previous=c0, current=c1). c0 must NO LONGER get in.
    let s0 = server(port, c0.cfg()).await;
    let r = connect_to(&trust, port).await;
    assert!(
        r.is_err(),
        "the previous generation got into a handshake — the two roles are mixed"
    );
    s0.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_certificate_is_rejected() {
    nettls::install_crypto_provider();

    let c0 = generation();
    let foreign = generation();
    let port = free_port();

    let trust = Trust::from_approval(
        Generation::from_der(c0.material.cert_chain()[0].as_ref().to_vec()).unwrap(),
    );

    let s = server(port, foreign.cfg()).await;
    let r = connect_to(&trust, port).await;
    assert!(r.is_err(), "an unknown certificate was accepted (§6.8b)");
    s.abort();
}

impl Gen {
    /// Server configuration for this generation.
    fn cfg(&self) -> Arc<rustls::ServerConfig> {
        self.material.server_config().expect("server config")
    }

    /// The fingerprint as §6 uses it: the bare hex `fingerprint_sha256()` gives.
    fn fp_bar(&self) -> String {
        self.fp.clone()
    }
}

// --------------------------------------------------------------------------- //
// 3.6 — the announcer actually drives a rotation, end to end
// --------------------------------------------------------------------------- //

/// The whole cycle over real TCP: announce → the client stores → receipt →
/// swap → the client connects to the new one **without having been told
/// when**.
///
/// And the actual gate: **the server does not swap before the receipt is in.**
/// Roll before the peer has stored the new one, and the peer's handshake
/// fails that very moment — exactly the break §6 exists to avoid.
#[tokio::test(flavor = "multi_thread")]
async fn announcer_rolls_only_when_receipt_is_in() {
    use nettls::RotatingResolver;
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};

    nettls::install_crypto_provider();

    let c0 = generation();
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("nettls-36-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    c0.material.save_pem(&dir).unwrap();

    let resolver = Arc::new(RotatingResolver::new(&c0.material).unwrap());
    let announcer = Announcer::new(
        "gateway",
        &dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        resolver.clone(),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        None,
    )
    .unwrap();

    // A server that reads the resolver live — it swaps when the resolver does.
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let r = resolver.clone();
    let srv = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let cfg = r.server_config().unwrap();
            tokio::spawn(async move {
                let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                if let Ok(mut s) = acceptor.accept(tcp).await {
                    let _ = s.write_all(b"hey").await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });

    let trust = Trust::from_approval(
        Generation::from_der(c0.material.cert_chain()[0].as_ref().to_vec()).unwrap(),
    );
    connect_to(&trust, port).await.expect("c0 must pass");

    // Announce.
    assert!(announcer.should_announce(100).unwrap());
    let k = announcer.prepare(100).expect("announcement");
    let new_fp = k.new_fingerprint().to_string();

    // Without a receipt NOTHING may happen — the gate in §6.8a.
    assert!(
        announcer.roll_if_ready(200).unwrap().is_none(),
        "rolled without a receipt — the gate in §6.8a does not hold"
    );
    connect_to(&trust, port).await.expect("must still be c0");

    // The client stores and acknowledges.
    trust
        .receive(&k, "gateway")
        .expect("the client stores the new one");
    let (receipt, key) = receipt_for(&announcer, "service");
    announcer.acked("service", &receipt, &key).unwrap();

    // Now we roll.
    let old = announcer
        .roll_if_ready(200)
        .unwrap()
        .expect("should have rolled now");
    assert!(old.contains(&c0.fp_bar()), "old fp: {old}");

    // The client connects to the new one without being told when the swap happened.
    connect_to(&trust, port)
        .await
        .expect("the announced successor was not accepted after the swap");
    assert_eq!(trust.state().unwrap().current().fingerprint(), new_fp);

    // And the rate limit blocks an immediate new round (M-22).
    assert!(!announcer.should_announce(201).unwrap());

    srv.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// **M-26** — an announced-and-acked promise survives a restart.
///
/// Not "the fields are preserved", but what actually matters: a **new**
/// `Announcer` built from disk keeps the promise the previous one gave. The
/// peer has acked and awaits the new certificate; forget it, and the peer is
/// left holding a promise nobody keeps.
#[tokio::test(flavor = "multi_thread")]
async fn the_promise_survives_a_restart() {
    use nettls::RotatingResolver;
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};

    nettls::install_crypto_provider();

    let c0 = generation();
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("nettls-m26-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    c0.material.save_pem(&dir).unwrap();

    let resolver = Arc::new(RotatingResolver::new(&c0.material).unwrap());
    let params = SelfSignedParams::new("localhost", ["localhost"]);

    // --- "before restart" ------------------------------------------------- //
    let k = {
        let announcer = Announcer::new(
            "gateway",
            &dir,
            params.clone(),
            resolver.clone(),
            OwnMaterial {
                previous: None,
                current: (c0.fp_bar(), c0.key()),
            },
            Schedule::new(vec!["service".to_string()], 0),
            None,
        )
        .unwrap();
        let k = announcer.prepare(100).unwrap();
        let (receipt, key) = receipt_for(&announcer, "service");
        announcer.acked("service", &receipt, &key).unwrap();
        announcer.save_pending().unwrap();
        k
    }; // announcer is dropped — the process "dies"

    // --- "after restart": everything is rebuilt from disk ------------------ //
    let restarted = Announcer::new(
        "gateway",
        &dir,
        params,
        resolver.clone(),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        None,
    )
    .unwrap();
    // `new` restores the promise itself (§6.17.3): the pending next must be
    // visible in the trio without any extra call.
    assert!(
        restarted.own_trio().unwrap().next_fingerprint.is_some(),
        "M-26 BROKEN: the promise was not read back"
    );
    assert_eq!(
        restarted.pending().unwrap().unwrap().new_fingerprint(),
        k.new_fingerprint(),
        "the restored promise covers a different certificate"
    );

    // The receipt from before the restart must still count — the peer must
    // not have to ack again for no reason.
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let r = resolver.clone();
    let srv = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let cfg = r.server_config().unwrap();
            tokio::spawn(async move {
                let a = tokio_rustls::TlsAcceptor::from(cfg);
                if let Ok(mut s) = a.accept(tcp).await {
                    let _ = s.write_all(b"hey").await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });

    let old = restarted
        .roll_if_ready(200)
        .unwrap()
        .expect("M-26 BROKEN: the receipt from before the restart did not count");
    assert!(old.contains(&c0.fp_bar()));

    // And the client that stored the announcement before the restart gets through afterwards.
    let trust = Trust::from_approval(
        Generation::from_der(c0.material.cert_chain()[0].as_ref().to_vec()).unwrap(),
    );
    trust.receive(&k, "gateway").unwrap();
    connect_to(&trust, port)
        .await
        .expect("the client does not reach the certificate promised before the restart");

    srv.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// **M-28/M-29** — the keys are locked at rest when a password is set.
///
/// This was the cross-check finding: `lockbox` existed as a primitive, the
/// requirement was noted as covered, and the `Announcer` still wrote `key.pem`
/// in cleartext. A primitive without a coupling is not a requirement
/// fulfilled.
#[tokio::test(flavor = "multi_thread")]
async fn keys_are_locked_when_password_is_set() {
    use nettls::RotatingResolver;
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};

    nettls::install_crypto_provider();

    let c0 = generation();
    let dir = std::env::temp_dir().join(format!("nettls-m28-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let pw = krypto::SecretString::from_string("secret".into()).unwrap();
    let announcer = Announcer::new(
        "gateway",
        &dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        Arc::new(RotatingResolver::new(&c0.material).unwrap()),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        Some(pw),
    )
    .unwrap();

    announcer.prepare(100).unwrap();

    // No cleartext key anywhere under the directory.
    let mut found_locked = false;
    for e in walk(&dir) {
        let name = e.file_name().unwrap().to_string_lossy().to_string();
        assert_ne!(
            name,
            nettls::KEY_FILE,
            "M-28 BROKEN: cleartext key on disk: {}",
            e.display()
        );
        if name == "material.locked" {
            found_locked = true;
            let b = std::fs::read(&e).unwrap();
            assert_eq!(&b[..8], b"NETTLS\x01\x00", "wrong file format");
            assert!(
                !String::from_utf8_lossy(&b).contains("PRIVATE KEY"),
                "M-28 BROKEN: the key is readable in the 'locked' file"
            );
            // Written through the crate's atomic writer, which sets the mode.
            // `fs::write` would have taken whatever the umask says — typically
            // 0644, so world-readable key material at rest.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&e).unwrap().permissions().mode() & 0o777;
                assert_eq!(
                    mode, 0o600,
                    "the locked material must not be readable by others"
                );
            }
        }
    }
    assert!(found_locked, "found no locked material file");

    // And the material can be read back — locking that cannot be unlocked is
    // not locking, it is loss.
    let (receipt, key) = receipt_for(&announcer, "service");
    announcer.acked("service", &receipt, &key).unwrap();
    assert!(
        announcer.roll_if_ready(200).unwrap().is_some(),
        "could not roll"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// **§6.17.1** — the `previous` key survives a restart after **two** rotations.
///
/// Reported by the reference implementation: a node that had rotated more than
/// once could, after a restart, neither sign nor verify the next announcement.
/// It was left with `current` but `previous = None`, because the previous key
/// lived only in memory.
///
/// The test does not check that a field is preserved, but what actually
/// matters: that a **new** `Announcer` built from disk can still produce a
/// **double-signed** announcement. If `previous` is gone, it becomes
/// single-signed — and then we are back to one key, which is the whole reason
/// §6 exists.
#[tokio::test(flavor = "multi_thread")]
async fn previous_key_survives_restart_after_two_rotations() {
    use nettls::RotatingResolver;
    use nettls::announcer::{Announcer, DAY_S, OwnMaterial, Schedule};

    nettls::install_crypto_provider();

    let c0 = generation();
    let dir = std::env::temp_dir().join(format!("nettls-617-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    c0.material.save_pem(&dir).unwrap();

    let resolver = Arc::new(RotatingResolver::new(&c0.material).unwrap());
    let params = SelfSignedParams::new("localhost", ["localhost"]);
    let t1 = 100;
    let t2 = t1 + DAY_S + 1;
    let t3 = t2 + DAY_S + 1;

    let build = |material| {
        Announcer::new(
            "gateway",
            &dir,
            params.clone(),
            resolver.clone(),
            material,
            Schedule::new(vec!["service".to_string()], 0),
            None,
        )
    };
    let gen0 = || OwnMaterial {
        previous: None,
        current: (c0.fp_bar(), c0.key()),
    };

    // --- "before restart": rotate twice ------------------------------------ //
    {
        let announcer = build(gen0()).unwrap();
        for t in [t1, t2] {
            announcer.prepare(t).unwrap();
            let (receipt, key) = receipt_for(&announcer, "service");
            announcer.acked("service", &receipt, &key).unwrap();
            announcer
                .roll_if_ready(t)
                .unwrap()
                .unwrap_or_else(|| panic!("the rotation at {t} did not happen"));
        }
    } // announcer is dropped — the process "dies"

    // --- "after restart" --------------------------------------------------- //
    // The consumer can only supply generation 0: the keys from gen 1 onwards
    // are made and owned by the crate, and never leave it. `new` restores the
    // chain itself (§6.17.3) — the trio must show a previous straight away.
    let restarted = build(gen0()).unwrap();
    assert!(
        restarted.own_trio().unwrap().previous_fingerprint.is_some(),
        "§6.17.1 BROKEN: the chain was not read back from disk"
    );

    let k = restarted.prepare(t3).unwrap();
    assert!(
        !k.is_bootstrap(),
        "§6.17.1 BROKEN: the announcement is single-signed — the previous key \
         did not survive the restart, and we are back to one key"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The A4/A5 switch point (SPEC-nettls §6.7e): the consumer's gate has the last
/// word, and a `false` postpones with **no side effects**.
#[tokio::test(flavor = "multi_thread")]
async fn the_gate_postpones_the_switch_without_side_effects() {
    use nettls::RotatingResolver;
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};

    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = std::env::temp_dir().join(format!("nettls-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    c0.material.save_pem(&dir).unwrap();

    let resolver = std::sync::Arc::new(RotatingResolver::new(&c0.material).unwrap());
    let announcer = Announcer::new(
        "gateway",
        &dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        resolver.clone(),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        None,
    )
    .unwrap();

    announcer.prepare(100).unwrap();
    let (receipt, key) = receipt_for(&announcer, "service");
    announcer.acked("service", &receipt, &key).unwrap();

    // Everything is ready — but the consumer says "not now".
    let before = resolver.fingerprint_sha256().unwrap();
    assert!(
        announcer
            .roll_if_ready_gated(100, || false)
            .unwrap()
            .is_none(),
        "a false gate must postpone the switch"
    );
    assert_eq!(
        resolver.fingerprint_sha256().unwrap(),
        before,
        "the resolver must be untouched after a postponed switch"
    );
    assert!(
        announcer.own_trio().unwrap().next_fingerprint.is_some(),
        "the pending promise must survive a postponed switch"
    );

    // Same call, gate open: the chain and the serving switch together.
    let old = announcer
        .roll_if_ready_gated(100, || true)
        .unwrap()
        .expect("with an open gate the switch must happen");
    assert_eq!(old, before, "swap must return the fingerprint we served");
    assert_ne!(resolver.fingerprint_sha256().unwrap(), before);
    assert!(announcer.own_trio().unwrap().previous_fingerprint.is_some());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A server with `cert`'s certificate and `key`'s private key.
fn cfg_with_foreign_key(cert: &Gen, key: &Gen) -> Arc<rustls::ServerConfig> {
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
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key_der = key
        .pkcs8
        .expose(|k| rustls::pki_types::PrivateKeyDer::Pkcs8(k.to_vec().into()));
    let signer = provider
        .key_provider
        .load_private_key(key_der)
        .expect("signing key");
    // `CertifiedKey::new` does not check that key and certificate match.
    let ck = rustls::sign::CertifiedKey::new(vec![cert.material.cert_chain()[0].clone()], signer);
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(Arc::new(ck)))),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn next_without_its_key_does_not_promote() {
    // `next` is public; presenting it without its key must change nothing.
    nettls::install_crypto_provider();

    let c0 = generation();
    let c1 = generation();
    let stranger = generation();
    let port = free_port();

    let trust = Trust::from_approval(
        Generation::from_der(c0.material.cert_chain()[0].as_ref().to_vec()).unwrap(),
    );
    let k = Announcement::new("gateway", None, (&c0.fp_bar(), &c0.pkcs8), &c1.pem, 1).unwrap();
    trust
        .receive(&k, "gateway")
        .expect("the announcement must be accepted");

    let s = server(port, cfg_with_foreign_key(&c1, &stranger)).await;
    assert!(
        connect_to(&trust, port).await.is_err(),
        "a handshake without the key must fail"
    );
    s.abort();

    let g = trust.state().unwrap();
    assert_eq!(
        g.current().fingerprint(),
        c0.fp_bar(),
        "the state moved without proof of the key"
    );
    assert_eq!(g.next().unwrap().fingerprint(), c1.fp_bar());
    assert!(g.previous().is_none());

    // The real successor still gets through, and promotes.
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let s1 = server(port, c1.cfg()).await;
    connect_to(&trust, port)
        .await
        .expect("the real successor must get through");
    assert_eq!(trust.state().unwrap().current().fingerprint(), c1.fp_bar());
    s1.abort();
}

/// A fresh directory holding `c0` as the material.
fn dir_with(name: &str, c0: &Gen) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("nettls-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    c0.material.save_pem(&dir).unwrap();
    dir
}

/// The announcer a process builds at start, with `c0` as the anchor.
fn announcer_in(
    dir: &std::path::Path,
    c0: &Gen,
    resolver: &Arc<nettls::RotatingResolver>,
) -> nettls::announcer::Announcer {
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};
    Announcer::new(
        "gateway",
        dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        resolver.clone(),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        None,
    )
    .unwrap()
}

/// The Ed25519 seed the peers in these tests sign with.
const PEER_SEED: [u8; 32] = [7; 32];

/// A receipt from `peer` for `a`'s pending announcement, and the key pinned for
/// `peer` that it verifies against.
fn receipt_for(a: &nettls::announcer::Announcer, peer: &str) -> (Receipt, Vec<u8>) {
    let k = a.pending().unwrap().expect("an announcement is pending");
    let seed = krypto::SecretBuf::from_vec(PEER_SEED.to_vec()).expect("mlock");
    let key = krypto::sign::ed25519_public(&seed).unwrap().to_vec();
    let receipt = Receipt::new(peer, k.announcer(), k.new_fingerprint(), 100, &seed).unwrap();
    (receipt, key)
}

#[test]
fn an_acknowledgement_is_verified_before_the_name_is_struck() {
    // 0.12.0: `acked` and `acked_handled` take the message and verify it. A
    // refusal changes neither the waiting list nor the saved promise.
    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = dir_with("acked-verifies", &c0);
    let resolver = Arc::new(nettls::RotatingResolver::new(&c0.material).unwrap());
    let a = announcer_in(&dir, &c0, &resolver);
    let k = a.prepare(100).unwrap();
    let fp = k.new_fingerprint();
    let (valid, key) = receipt_for(&a, "service");
    let seed = krypto::SecretBuf::from_vec(PEER_SEED.to_vec()).unwrap();
    let other_key =
        krypto::sign::ed25519_public(&krypto::SecretBuf::from_vec(vec![9; 32]).unwrap()).unwrap();
    let other_fp = "bb".repeat(32);
    let promise = dir.join(nettls::announcer::PENDING_FILE);
    let waiting = || a.status(0, 0).unwrap().waiting_for;
    let saved = std::fs::read(&promise).unwrap();

    let refused = [
        (
            "service",
            valid.clone(),
            other_key.as_slice(),
            "does not hold",
        ),
        (
            "service",
            Receipt::new("service", "gateway", &other_fp, 100, &seed).unwrap(),
            key.as_slice(),
            "a different rotation",
        ),
        (
            "service",
            Receipt::new("service", "portal", fp, 100, &seed).unwrap(),
            key.as_slice(),
            "for another announcer",
        ),
        (
            "stranger",
            Receipt::new("stranger", "gateway", fp, 100, &seed).unwrap(),
            key.as_slice(),
            "not one of the peers",
        ),
    ];
    for (peer, receipt, pinned, why) in refused {
        let err = a.acked(peer, &receipt, pinned).unwrap_err();
        assert!(matches!(err, nettls::TlsError::ProofInvalid(_)), "{err:?}");
        assert!(err.to_string().contains(why), "{err}");
        assert_eq!(waiting(), ["service"]);
        assert_eq!(std::fs::read(&promise).unwrap(), saved);
    }

    // A handled message is verified the same way.
    let handled = Handled::new("service", "gateway", fp, 100, &seed).unwrap();
    let err = a
        .acked_handled("service", &handled, &other_key)
        .unwrap_err();
    assert!(err.to_string().contains("does not hold"), "{err}");
    assert_eq!(waiting(), ["service"]);
    assert_eq!(std::fs::read(&promise).unwrap(), saved);

    a.acked("service", &valid, &key).unwrap();
    assert!(waiting().is_empty());
    // Having acknowledged does not let an invalid message through.
    assert!(a.acked("service", &valid, &other_key).is_err());

    // The receipt again, and then a handled message: both `Ok`, and nothing changes.
    let saved = std::fs::read(&promise).unwrap();
    a.acked("service", &valid, &key).unwrap();
    a.acked_handled("service", &handled, &key).unwrap();
    assert!(waiting().is_empty());
    assert_eq!(std::fs::read(&promise).unwrap(), saved);

    // After the switch nothing is announced, and the same receipt came late.
    assert!(a.roll_if_ready(200).unwrap().is_some());
    let err = a.acked("service", &valid, &key).unwrap_err();
    assert!(err.to_string().contains("came late"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_handled_message_alone_lets_the_switch_happen() {
    // 0.12.0: the receipt is lost on the way; the handled message that
    // follows it counts as the acknowledgement.
    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = dir_with("handled-alone", &c0);
    let resolver = Arc::new(nettls::RotatingResolver::new(&c0.material).unwrap());
    let a = announcer_in(&dir, &c0, &resolver);
    let k = a.prepare(100).unwrap();
    let (_lost, key) = receipt_for(&a, "service");
    let seed = krypto::SecretBuf::from_vec(PEER_SEED.to_vec()).unwrap();
    let handled = Handled::new("service", "gateway", k.new_fingerprint(), 100, &seed).unwrap();

    a.acked_handled("service", &handled, &key).unwrap();
    assert!(a.roll_if_ready(200).unwrap().is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_promise_and_the_switch_survive_restarts_without_save_pending() {
    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = dir_with("promise", &c0);
    let resolver = Arc::new(nettls::RotatingResolver::new(&c0.material).unwrap());

    let a = announcer_in(&dir, &c0, &resolver);
    let k = a.prepare(100).unwrap();
    let (receipt, key) = receipt_for(&a, "service");
    a.acked("service", &receipt, &key).unwrap();
    drop(a);

    let b = announcer_in(&dir, &c0, &resolver);
    assert_eq!(
        b.pending().unwrap().unwrap().new_fingerprint(),
        k.new_fingerprint()
    );
    assert!(
        b.roll_if_ready(200).unwrap().is_some(),
        "the receipt was lost"
    );
    assert!(!dir.join(nettls::announcer::PENDING_FILE).exists());
    assert!(!dir.join("new").exists());
    drop(b);

    let c = announcer_in(&dir, &c0, &resolver);
    let trio = c.own_trio().unwrap();
    assert_eq!(trio.current_fingerprint, k.new_fingerprint());
    assert_eq!(trio.previous_fingerprint.unwrap(), c0.fp_bar());
    assert!(trio.next_fingerprint.is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_write_changes_nothing_and_the_next_call_switches() {
    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = dir_with("failed-write", &c0);
    let resolver = Arc::new(nettls::RotatingResolver::new(&c0.material).unwrap());
    let a = announcer_in(&dir, &c0, &resolver);
    let k = a.prepare(100).unwrap();
    let (receipt, key) = receipt_for(&a, "service");
    a.acked("service", &receipt, &key).unwrap();

    // A directory where the previous key is to be written makes that write fail.
    let blocker = dir.join("previous-key.json");
    std::fs::create_dir(&blocker).unwrap();
    assert!(a.roll_if_ready(200).is_err());
    let trio = a.own_trio().unwrap();
    assert_eq!(trio.current_fingerprint, c0.fp_bar());
    assert_eq!(trio.next_fingerprint.as_deref(), Some(k.new_fingerprint()));
    let on_disk = TlsMaterial::load(&CertSource::files(
        dir.join(nettls::CERT_FILE),
        dir.join(nettls::KEY_FILE),
    ))
    .unwrap();
    assert_eq!(on_disk.fingerprint_sha256(), c0.fp);

    std::fs::remove_dir(&blocker).unwrap();
    assert!(a.roll_if_ready(201).unwrap().is_some());
    assert_eq!(
        a.own_trio().unwrap().current_fingerprint,
        k.new_fingerprint()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_switch_refuses_material_that_is_not_what_was_announced() {
    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = dir_with("not-announced", &c0);
    let resolver = Arc::new(nettls::RotatingResolver::new(&c0.material).unwrap());
    let a = announcer_in(&dir, &c0, &resolver);
    let k = a.prepare(100).unwrap();
    let (receipt, key) = receipt_for(&a, "service");
    a.acked("service", &receipt, &key).unwrap();

    // Something else now lies where the announced certificate was put.
    let other = generation();
    other.material.save_pem(&dir.join("new")).unwrap();

    let err = a.roll_if_ready(200).unwrap_err();
    assert!(format!("{err}").contains("was announced"), "{err}");
    assert_eq!(resolver.fingerprint_sha256().unwrap(), c0.fp_bar());
    let trio = a.own_trio().unwrap();
    assert_eq!(trio.current_fingerprint, c0.fp_bar());
    assert_eq!(trio.next_fingerprint.as_deref(), Some(k.new_fingerprint()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn after_a_restart_the_resolver_serves_the_restored_certificate() {
    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = dir_with("restart-serves", &c0);
    // As a service does at every start: the resolver is built from the anchor.
    let start = || {
        let resolver = Arc::new(nettls::RotatingResolver::new(&c0.material).unwrap());
        let announcer = announcer_in(&dir, &c0, &resolver);
        (resolver, announcer)
    };

    let (_, first) = start();
    first.prepare(100).unwrap();
    let (receipt, key) = receipt_for(&first, "service");
    first.acked("service", &receipt, &key).unwrap();
    assert!(first.roll_if_ready(200).unwrap().is_some());
    let rolled = first.own_trio().unwrap().current_fingerprint;
    assert_ne!(rolled, c0.fp_bar());
    drop(first);

    let (resolver, second) = start();
    assert_eq!(second.own_trio().unwrap().current_fingerprint, rolled);
    assert_eq!(
        resolver.fingerprint_sha256().unwrap(),
        rolled,
        "the server must present what the chain says is current"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_daily_cap_holds_across_a_restart() {
    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = dir_with("cap", &c0);
    let resolver = Arc::new(nettls::RotatingResolver::new(&c0.material).unwrap());
    let a = announcer_in(&dir, &c0, &resolver);
    a.prepare(100).unwrap();
    let (receipt, key) = receipt_for(&a, "service");
    a.acked("service", &receipt, &key).unwrap();
    assert!(a.roll_if_ready(200).unwrap().is_some());
    drop(a);

    let b = announcer_in(&dir, &c0, &resolver);
    b.prepare(300).unwrap();
    let (receipt, key) = receipt_for(&b, "service");
    b.acked("service", &receipt, &key).unwrap();
    assert!(
        b.roll_if_ready(400).unwrap().is_none(),
        "a restart must not reset the 24-hour cap"
    );
    let day = nettls::announcer::MIN_BETWEEN_ROLLS_S;
    assert!(b.roll_if_ready(200 + day).unwrap().is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

/// An `Announcer` with a password, in a fresh directory.
fn announcer_with_password(dir: &std::path::Path) -> nettls::announcer::Announcer {
    announcer_for(dir, &generation(), &["service"])
}

/// An `Announcer` with a password over `dir`, anchored in `c0`, waiting for
/// `peers` — as a service builds one at every start.
fn announcer_for(dir: &std::path::Path, c0: &Gen, peers: &[&str]) -> nettls::announcer::Announcer {
    use nettls::RotatingResolver;
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};

    Announcer::new(
        "gateway",
        dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        Arc::new(RotatingResolver::new(&c0.material).unwrap()),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(peers.iter().map(|p| p.to_string()).collect::<Vec<_>>(), 0),
        Some(krypto::SecretString::from_string("secret".into()).unwrap()),
    )
    .unwrap()
}

#[test]
fn a_password_over_krypto_limit_is_refused_at_construction() {
    // 0.12.0: refused before anything on disk is read or written, with the
    // answer the lockbox gives for it.
    use nettls::RotatingResolver;
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};

    nettls::install_crypto_provider();
    let dir = std::env::temp_dir().join(format!("nettls-fs0162-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let c0 = generation();
    let max = krypto::password::MAX_PASSWORD_BYTES;
    let err = Announcer::new(
        "gateway",
        &dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        Arc::new(RotatingResolver::new(&c0.material).unwrap()),
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        Some(krypto::SecretString::from_string("p".repeat(max + 1)).unwrap()),
    )
    .err()
    .expect("a password over the limit is refused");
    assert!(matches!(err, nettls::TlsError::Params(_)), "{err:?}");
    assert!(
        err.to_string()
            .contains(&format!("password is {} bytes — max {max}", max + 1)),
        "{err}"
    );
    assert!(
        std::fs::read_dir(&dir).unwrap().next().is_none(),
        "the refused announcer created something in {}",
        dir.display()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saving_with_a_password_writes_nothing_in_cleartext_first() {
    // Up to 0.10 `save` wrote the key in cleartext to `.tmp-material/`, then
    // read it back, locked it and deleted the directory. Now it is built and
    // locked in memory: a staging directory planted where it used to be is
    // neither written to nor removed (0.11.0).
    nettls::install_crypto_provider();
    let dir = std::env::temp_dir().join(format!("nettls-fs0073-a-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let announcer = announcer_with_password(&dir);

    let staging = dir.join("new").join(".tmp-material");
    std::fs::create_dir_all(&staging).unwrap();
    announcer.prepare(100).unwrap();

    assert!(staging.is_dir(), "save went through the staging directory");
    assert!(
        std::fs::read_dir(&staging).unwrap().next().is_none(),
        "save wrote to the staging directory"
    );
    assert!(dir.join("new").join("material.locked").is_file());

    // And what was locked in memory reads back.
    let (receipt, key) = receipt_for(&announcer, "service");
    announcer.acked("service", &receipt, &key).unwrap();
    assert!(
        announcer.roll_if_ready(200).unwrap().is_some(),
        "could not roll"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_cleartext_key_left_by_an_old_crash_is_removed_at_start() {
    // A crash under 0.10 between writing and deleting `.tmp-material/` left
    // the key there in cleartext. The next start removes it (0.11.0).
    nettls::install_crypto_provider();
    let dir = std::env::temp_dir().join(format!("nettls-fs0073-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let left = [
        dir.join(".tmp-material"),
        dir.join("new").join(".tmp-material"),
    ];
    for d in &left {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join(nettls::KEY_FILE), b"-----BEGIN PRIVATE KEY-----\n").unwrap();
    }

    let _announcer = announcer_with_password(&dir);

    for d in &left {
        assert!(
            !d.exists(),
            "a cleartext key is still on disk: {}",
            d.display()
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_pending_file_that_cannot_be_removed_is_an_error_that_says_why() {
    // With nothing pending, `save_pending` removes an old promise. A failure
    // used to be ignored; it is now an error naming the file and what a
    // leftover would do (0.11.0).
    nettls::install_crypto_provider();
    let dir = std::env::temp_dir().join(format!("nettls-fs0075-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let announcer = announcer_with_password(&dir);

    // A directory where the file should be: removing it as a file fails.
    let promise = dir.join(nettls::announcer::PENDING_FILE);
    std::fs::create_dir_all(&promise).unwrap();
    let err = announcer.save_pending().unwrap_err().to_string();
    assert!(err.contains(nettls::announcer::PENDING_FILE), "{err}");
    assert!(err.contains("nothing is pending"), "{err}");
    assert!(err.contains("promised rotation"), "{err}");

    // Nothing there is fine.
    std::fs::remove_dir(&promise).unwrap();
    announcer.save_pending().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_peer_removed_while_waiting_no_longer_blocks_the_rotation() {
    // Without `Announcer::remove_peer` a decommissioned module blocked every
    // rotation for good (0.11.0).
    nettls::install_crypto_provider();
    let dir = std::env::temp_dir().join(format!("nettls-fs0076-a-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let announcer = announcer_for(&dir, &generation(), &["service", "portal"]);

    announcer.prepare(100).unwrap();
    let (receipt, key) = receipt_for(&announcer, "service");
    announcer.acked("service", &receipt, &key).unwrap();
    assert!(
        announcer.roll_if_ready(200).unwrap().is_none(),
        "rolled without portal"
    );
    announcer.remove_peer("portal").unwrap();
    assert!(
        announcer.roll_if_ready(200).unwrap().is_some(),
        "portal still blocks"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_peer_added_while_waiting_must_ack_too() {
    nettls::install_crypto_provider();
    let dir = std::env::temp_dir().join(format!("nettls-fs0076-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let announcer = announcer_for(&dir, &generation(), &["service"]);

    announcer.prepare(100).unwrap();
    announcer.add_peer("portal").unwrap();
    let (receipt, key) = receipt_for(&announcer, "service");
    announcer.acked("service", &receipt, &key).unwrap();
    assert!(
        announcer.roll_if_ready(200).unwrap().is_none(),
        "rolled without portal"
    );
    let (receipt, key) = receipt_for(&announcer, "portal");
    announcer.acked("portal", &receipt, &key).unwrap();
    assert!(
        announcer.roll_if_ready(200).unwrap().is_some(),
        "could not roll"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn after_a_restart_a_peer_taken_out_of_the_list_is_not_waited_for() {
    // The waiting list on disk names `portal`; the consumer's list at the
    // next start does not. Before 0.11.0 the restart kept waiting for it.
    nettls::install_crypto_provider();
    let dir = std::env::temp_dir().join(format!("nettls-fs0076-c-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let c0 = generation();
    {
        let announcer = announcer_for(&dir, &c0, &["service", "portal"]);
        announcer.prepare(100).unwrap();
        let (receipt, key) = receipt_for(&announcer, "service");
        announcer.acked("service", &receipt, &key).unwrap();
    } // the process "dies"

    let announcer = announcer_for(&dir, &c0, &["service"]);
    assert!(
        announcer.roll_if_ready(200).unwrap().is_some(),
        "the restart still waits for a peer that is no longer in the list"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rotates once without a password in a fresh directory named after `name`,
/// lets `edit` change `previous-key.json`, and builds the announcer again over
/// the same directory, as the next start would.
fn restart_after_editing_previous_key(
    name: &str,
    edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> Result<nettls::announcer::Announcer, nettls::TlsError> {
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};

    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = dir_with(name, &c0);
    let resolver = Arc::new(nettls::RotatingResolver::new(&c0.material).unwrap());
    let a = announcer_in(&dir, &c0, &resolver);
    a.prepare(100).unwrap();
    let (receipt, key) = receipt_for(&a, "service");
    a.acked("service", &receipt, &key).unwrap();
    assert!(a.roll_if_ready(200).unwrap().is_some(), "could not roll");
    drop(a);

    let file = dir.join("previous-key.json");
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    edit(
        json.as_object_mut()
            .expect("the previous key is a JSON object"),
    );
    std::fs::write(&file, serde_json::to_vec(&json).unwrap()).unwrap();

    let restarted = Announcer::new(
        "gateway",
        &dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        resolver,
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        None,
    );
    let _ = std::fs::remove_dir_all(&dir);
    restarted
}

#[test]
fn a_previous_key_without_current_is_refused_at_start() {
    let err = restart_after_editing_previous_key("prev-no-current", |m| {
        m.remove("current");
    })
    .err()
    .expect("a previous key without `current` is refused");
    assert!(matches!(err, nettls::TlsError::Chain(_)), "{err:?}");
    assert!(
        err.to_string().contains("which certificate it belongs to"),
        "{err}"
    );
    assert!(err.to_string().contains("0.10.0"), "{err}");
}

#[test]
fn a_previous_key_without_rolled_at_is_refused_at_start() {
    let err = restart_after_editing_previous_key("prev-no-rolled-at", |m| {
        m.remove("rolled_at");
    })
    .err()
    .expect("a previous key without `rolled_at` is refused");
    assert!(matches!(err, nettls::TlsError::Chain(_)), "{err:?}");
    assert!(
        err.to_string()
            .contains("does not say when the pair came about"),
        "{err}"
    );
    assert!(err.to_string().contains("0.10.0"), "{err}");
}

#[test]
fn a_previous_key_for_another_certificate_is_refused_at_start() {
    let err = restart_after_editing_previous_key("prev-other-current", |m| {
        m.insert("current".into(), serde_json::Value::String("ab".repeat(32)));
    })
    .err()
    .expect("a previous key that belongs to another certificate is refused");
    assert!(matches!(err, nettls::TlsError::Chain(_)), "{err:?}");
    assert!(err.to_string().contains("but the material in"), "{err}");
}

#[test]
fn a_previous_key_file_with_an_unknown_key_is_refused_at_start() {
    let err = restart_after_editing_previous_key("prev-unknown-key", |m| {
        m.insert("extra".into(), 1.into());
    })
    .err()
    .expect("a previous key file with an unknown key is refused");
    assert!(matches!(err, nettls::TlsError::Chain(_)), "{err:?}");
    assert!(err.to_string().contains("unknown field `extra`"), "{err}");
}

#[test]
fn a_pending_file_with_an_unknown_key_is_refused_at_start() {
    use nettls::announcer::{Announcer, OwnMaterial, Schedule};

    nettls::install_crypto_provider();
    let c0 = generation();
    let dir = dir_with("pending-unknown-key", &c0);
    let resolver = Arc::new(nettls::RotatingResolver::new(&c0.material).unwrap());
    announcer_in(&dir, &c0, &resolver).prepare(100).unwrap();

    let file = dir.join(nettls::announcer::PENDING_FILE);
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    json["extra"] = 1.into();
    std::fs::write(&file, serde_json::to_vec(&json).unwrap()).unwrap();

    let err = Announcer::new(
        "gateway",
        &dir,
        SelfSignedParams::new("localhost", ["localhost"]),
        resolver,
        OwnMaterial {
            previous: None,
            current: (c0.fp_bar(), c0.key()),
        },
        Schedule::new(vec!["service".to_string()], 0),
        None,
    )
    .err()
    .expect("a pending file with an unknown key is refused");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(matches!(err, nettls::TlsError::Proof(_)), "{err:?}");
    assert!(err.to_string().contains("unknown field `extra`"), "{err}");
}
