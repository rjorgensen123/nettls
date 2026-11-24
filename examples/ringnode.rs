// SPDX-License-Identifier: MIT OR Apache-2.0
//! A ring node in Rust (SPEC-nettls §6.15): a test of the functionality that
//! shows nettls working in a ring. It is a test tool, not a finished
//! implementation of a node.
//!
//! This is the **strict** node. `nettls-py/tests/ringnode.py` is the
//! **relaxed** one, which only uses the functionality, in the simplest way.
//! The difference is deliberate. What this node checks:
//!
//! - `approve` compares the fingerprint of the certificate it is shown with
//!   `fp`, the one the operator expects, and pins nothing on a mismatch;
//! - `fetch_and_ack` signs a receipt only for a pinned peer whose announcement
//!   verified, and requires `{"ok": true}` in reply;
//! - a receipt that arrives with no announcement pending is refused;
//! - only `approve` connects unverified: a neighbour that is not pinned is an
//!   error, and `export` and `import` carry the neighbour's name;
//! - malformed input never stops the node: a request with a wrong field gets
//!   an error reply, and so does a control line that is not JSON or is too
//!   long; a network line that is not JSON or is too long closes that
//!   connection;
//! - bounds on line lengths, concurrent connections and `skip`, and I/O
//!   timeouts on every connection.
//!
//! The two speak the same protocol, one JSON line in and one out over TLS, and
//! work together in one ring: `test_ring_6_all_neighbourhoods` in
//! `nettls-py/tests/test_ring.py` shows it, and
//! `test_approve_with_wrong_fingerprint_rust_refuses_python_pins` there shows
//! the difference.
//!
//! Blocking I/O on purpose: a thread per connection is more than enough for
//! three nodes, and it keeps the test free of async machinery that could hide
//! a bug in what is actually being tested.
//!
//! ```text
//! cargo run --example ringnode -- <name> <port> <neighbour-port> <ed25519-seed-hex>
//! ```

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nettls::announcement::{Announcement, Receipt};
use nettls::announcer::{Mode, Schedule};
use nettls::generations::{Generation, Trust};
use nettls::{CertSource, SelfSignedParams, TlsMaterial};
use serde_json::{Value, json};

/// Read and write timeout on every connection, outgoing and accepted.
const IO_TIMEOUT: Duration = Duration::from_secs(20);
/// Longest line read from the network; the identity reply, the largest, is about two KiB.
const MAX_NETWORK_LINE: usize = 64 * 1024;
/// Longest line read from the control channel; `import`, the largest, is about five KiB with one peer.
const MAX_CONTROL_LINE: usize = 1024 * 1024;
/// Connections handled at the same time; a marker holds one per hop it has passed through.
const MAX_CONNECTIONS: usize = 128;
/// Largest `skip` for the marker; a ring needs its own length, and the tests use at most six.
const MAX_SKIP: i64 = 64;

struct Node {
    name: String,
    port: u16,
    neighbour_port: u16,
    /// The successor's name. Without it the marker path cannot pin, and it
    /// refuses to connect.
    neighbour_name: Mutex<Option<String>>,
    seed: krypto::SecretBuf,
    /// Our own material: (fingerprint, cert_pem, pkcs8).
    current: Mutex<(String, String, Arc<krypto::SecretBuf>)>,
    previous: Mutex<Option<(String, String, Arc<krypto::SecretBuf>)>>,
    /// Announced, not yet taken into use.
    pending: Mutex<Option<(Announcement, String, Arc<krypto::SecretBuf>)>>,
    schedule: Mutex<Schedule>,
    peers: Mutex<HashMap<String, Trust>>,
    peer_keys: Mutex<HashMap<String, Vec<u8>>>,
    rotations: Mutex<u32>,
    /// Who must ack OUR rotations. `Schedule` has no getter for the set, and
    /// the consumer is the one who remembers anyway.
    ackers: Mutex<Vec<String>>,
}

fn make_material(name: &str) -> (String, String, Arc<krypto::SecretBuf>) {
    let m = TlsMaterial::load(&CertSource::self_signed(
        SelfSignedParams::new(name, ["localhost", "127.0.0.1"]).valid_days(30),
    ))
    .expect("self-signed");
    let der = m.cert_chain()[0].as_ref().to_vec();
    let pem = String::from_utf8(nettls::pem::encode("CERTIFICATE", &der).expect("pem")).unwrap();
    let fp = m.fingerprint_sha256().replace("sha256:", "");
    let pkcs8 = Arc::new(m.anchor_pkcs8().expect("pkcs8"));
    (fp, pem, pkcs8)
}

impl Node {
    fn new(name: &str, port: u16, neighbour_port: u16, seed: Vec<u8>) -> Self {
        let m = make_material(name);
        Self {
            name: name.to_string(),
            port,
            neighbour_port,
            neighbour_name: Mutex::new(None),
            seed: krypto::SecretBuf::from_vec(seed).expect("seed"),
            current: Mutex::new(m),
            previous: Mutex::new(None),
            pending: Mutex::new(None),
            schedule: Mutex::new(Schedule::new(Vec::<String>::new(), 0)),
            peers: Mutex::new(HashMap::new()),
            peer_keys: Mutex::new(HashMap::new()),
            rotations: Mutex::new(0),
            ackers: Mutex::new(Vec::new()),
        }
    }

    /// Server configuration built **per connection**, from the live material.
    /// A cached config would have served the old certificate after a rotation
    /// — i.e. exactly the divergence between what we advertise and what we
    /// present.
    fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        let (_, cert, key) = self.current.lock().unwrap().clone();
        let key_pem = String::from_utf8(
            key.expose(|k| nettls::pem::encode("PRIVATE KEY", k))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        TlsMaterial::load(&CertSource::pem(cert.into_bytes(), key_pem.into_bytes()))
            .and_then(|m| m.server_config())
            .map_err(|e| e.to_string())
    }

    fn handle(&self, m: &Value) -> Value {
        match m["op"].as_str().unwrap_or("") {
            "identity" => {
                let (fp, cert, _) = self.current.lock().unwrap().clone();
                let mut out = json!({
                    "fingerprint": format!("sha256:{fp}"),
                    "cert_pem": cert,
                    "mode": Mode::Rolling,
                    "sent_at": now(),
                });
                if let Some((k, _, _)) = self.pending.lock().unwrap().as_ref() {
                    match k.to_json() {
                        Ok(j) => match serde_json::to_value(j) {
                            Ok(v) => out["announcement"] = v,
                            Err(e) => return json!({"error": e.to_string()}),
                        },
                        Err(e) => return json!({"error": e.to_string()}),
                    }
                }
                out
            }
            "ack" => {
                let ack_json: nettls::announcement::ReceiptJson =
                    match serde_json::from_value(m["receipt"].clone()) {
                        Ok(v) => v,
                        Err(e) => return json!({"error": format!("invalid receipt: {e}")}),
                    };
                let ack = match Receipt::from_json(&ack_json) {
                    Ok(v) => v,
                    Err(e) => return json!({"error": e.to_string()}),
                };
                // `.get`, not indexing: a receipt from an unknown acker is a
                // NORMAL hostile/misrouted message and must be an error reply,
                // not a panic (as the Python node does).
                let Some(pk) = self.peer_keys.lock().unwrap().get(ack.acker()).cloned() else {
                    return json!({"error": format!(
                        "receipt from unknown acker {:?} — no pinned Ed25519 key", ack.acker()
                    )});
                };
                // A receipt only means something for an announcement we have
                // made and not yet rolled; without one there is nothing to compare.
                let Some(expected) = self
                    .pending
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|(k, _, _)| k.new_fingerprint().to_string())
                else {
                    return json!({"error": format!(
                        "receipt from {:?}, but no announcement is pending", ack.acker()
                    )});
                };
                match ack.verify(ack.acker(), &pk, &expected) {
                    Ok(()) => {
                        self.schedule.lock().unwrap().acked(ack.acker());
                        json!({"ok": true})
                    }
                    Err(e) => json!({"error": e.to_string()}),
                }
            }
            "marker" => {
                let skip = m["skip"].as_i64().unwrap_or(0);
                if skip <= 0 {
                    return json!({"marker": m["marker"]});
                }
                if skip > MAX_SKIP {
                    return json!({"error": format!("marker: «skip» is above {MAX_SKIP}")});
                }
                // **Pinned, like all other traffic.** Without the neighbour's
                // name there is no pinned connection, and the marker is refused
                // rather than passed on unverified.
                let Some(nb) = self.neighbour_name.lock().unwrap().clone() else {
                    return json!({"error": "no pinned neighbour to pass the marker to"});
                };
                match self.talk(
                    self.neighbour_port,
                    &json!({"op":"marker","marker":m["marker"],"skip":skip-1}),
                    Some(&nb),
                ) {
                    Ok(reply) if reply.get("error").is_some() => json!({"error": reply["error"]}),
                    Ok(reply) => json!({"marker": reply["marker"]}),
                    Err(e) => json!({"error": format!("could not pass the marker on: {e}")}),
                }
            }
            op => json!({"error": format!("unknown op: {op}")}),
        }
    }

    /// One request to a neighbour. A named neighbour must be pinned, and the
    /// connection then accepts its `current` and `next` certificate; `None` is
    /// first contact, which only `approve` makes.
    fn talk(&self, port: u16, message: &Value, neighbour: Option<&str>) -> Result<Value, String> {
        nettls::install_crypto_provider();
        // `Trust` gives a config that accepts `current` + `next` and that
        // **promotes by itself** when it sees the swap in the handshake (§6.7).
        // That is why the node needs no observation logic of its own.
        let cfg = match neighbour {
            Some(nb) => match self.peers.lock().unwrap().get(nb).cloned() {
                Some(t) => t.client_config().map_err(|e| e.to_string())?,
                None => {
                    return Err(format!(
                        "{nb:?} is not pinned; only approve connects unverified"
                    ));
                }
            },
            None => nettls::unverified_client_config().map_err(|e| e.to_string())?,
        };

        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut conn = rustls::ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
        let mut tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        // A timeout so a hang becomes a READABLE error instead of a test that
        // stands for ten minutes without saying why.
        let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
        let mut s = rustls::Stream::new(&mut conn, &mut tcp);

        s.write_all(format!("{message}\n").as_bytes())
            .map_err(|e| e.to_string())?;
        s.flush().map_err(|e| e.to_string())?;

        let mut line = String::new();
        BufReader::new(&mut s)
            .take(MAX_NETWORK_LINE as u64 + 1)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        if line.len() > MAX_NETWORK_LINE {
            return Err(format!("the reply is longer than {MAX_NETWORK_LINE} bytes"));
        }
        serde_json::from_str(&line).map_err(|e| e.to_string())
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A snapshot of the trust in one peer, as a comparable value.
///
/// Used to establish that a rejected message did not get to change anything.
/// Without it, "rejected" would only mean the call returned an error — not
/// that the state stood untouched.
fn state_of(node: &Arc<Node>, name: &str) -> Option<(String, Option<String>, Option<String>)> {
    let mp = node.peers.lock().unwrap();
    let g = mp.get(name)?.state().ok()?;
    Some((
        g.current().fingerprint().to_string(),
        g.previous().map(|x| x.fingerprint().to_string()),
        g.next().map(|x| x.fingerprint().to_string()),
    ))
}

fn control(node: &Arc<Node>, m: &Value) -> Value {
    match m["op"].as_str().unwrap_or("") {
        "approve" => {
            let Some(port) = m["port"].as_u64().and_then(|p| u16::try_from(p).ok()) else {
                return json!({"error": "approve: «port» is missing or not a port number"});
            };
            let Some(name) = m["name"].as_str() else {
                return json!({"error": "approve: «name» is missing or not a string"});
            };
            // The fingerprint the operator expects, as bare hex. First contact
            // is unverified; comparing with this before anything is stored is
            // what makes it an approval.
            let Some(expected) = m["fp"].as_str() else {
                return json!({"error": "approve: «fp», the expected fingerprint, is missing or not a string"});
            };
            if let Err(e) = nettls::canonical::require_fingerprint(expected, "approve: «fp»") {
                return json!({"error": e.to_string()});
            }
            let key = match m["ed25519_pub"].as_str().map(nettls::signature::from_hex) {
                Some(Ok(k)) => k,
                Some(Err(e)) => return json!({"error": format!("approve: «ed25519_pub»: {e}")}),
                None => {
                    return json!({"error": "approve: «ed25519_pub» is missing or not a string"});
                }
            };
            let reply = match node.talk(port, &json!({"op":"identity"}), None) {
                Ok(v) => v,
                Err(e) => return json!({"error": format!("the neighbour did not answer: {e}")}),
            };
            let Some(cert_pem) = reply["cert_pem"].as_str() else {
                return json!({"error": "approve: the identity reply has no «cert_pem»"});
            };
            let g = match Generation::from_pem(cert_pem) {
                Ok(g) => g,
                Err(e) => return json!({"error": format!("approve: «cert_pem»: {e}")}),
            };
            let fp = g.fingerprint().to_string();
            if fp != expected {
                return json!({"error": format!(
                    "approve: the neighbour's certificate has fingerprint {fp}, not the expected {expected}; nothing is pinned"
                )});
            }
            let name = name.to_string();
            let _ = &name;
            node.peers
                .lock()
                .unwrap()
                .insert(name.clone(), Trust::from_approval(g));
            // If this is the successor in the ring, remember the name — the
            // marker path needs it to be able to pin.
            if port == node.neighbour_port {
                *node.neighbour_name.lock().unwrap() = Some(name.clone());
            }
            node.peer_keys.lock().unwrap().insert(name.clone(), key);
            json!({"ok": true, "fp": fp})
        }
        "require_ack_from" => {
            // Who must ack OUR rotation is whoever **pins us** — not whoever
            // we pin. The two edges differ, and mixing them makes you wait
            // forever for a receipt that was never meant to come.
            let Some(name) = m["name"].as_str() else {
                return json!({"error": "require_ack_from: «name» is missing or not a string"});
            };
            let name = name.to_string();
            node.schedule.lock().unwrap().add_peer(name.clone());
            node.ackers.lock().unwrap().push(name);
            json!({"ok": true})
        }
        "know_key" => {
            // Only the pinned Ed25519 key — no trust in a certificate.
            let Some(name) = m["name"].as_str() else {
                return json!({"error": "know_key: «name» is missing or not a string"});
            };
            let key = match m["ed25519_pub"].as_str().map(nettls::signature::from_hex) {
                Some(Ok(k)) => k,
                Some(Err(e)) => return json!({"error": format!("know_key: «ed25519_pub»: {e}")}),
                None => {
                    return json!({"error": "know_key: «ed25519_pub» is missing or not a string"});
                }
            };
            node.peer_keys.lock().unwrap().insert(name.to_string(), key);
            json!({"ok": true})
        }
        "prepare" => {
            let Some(now) = m["now"].as_i64() else {
                return json!({"error": "prepare: «now» is missing or not a whole number"});
            };
            if let Some((k, _, _)) = node.pending.lock().unwrap().as_ref() {
                return json!({"ok": true, "new_fp": k.new_fingerprint()});
            }
            let (fp_new, pem_new, key_new) = make_material(&node.name);
            let (fp, _, key) = node.current.lock().unwrap().clone();
            let previous = node.previous.lock().unwrap().clone();
            let k = match Announcement::new(
                &node.name,
                previous.as_ref().map(|(f, _, p)| (f.as_str(), p.as_ref())),
                (fp.as_str(), key.as_ref()),
                &pem_new,
                now,
            ) {
                Ok(k) => k,
                Err(e) => return json!({"error": format!("prepare: {e}")}),
            };
            let _ = fp_new;
            *node.pending.lock().unwrap() = Some((k.clone(), pem_new, key_new));
            node.schedule.lock().unwrap().announced(now);
            json!({"ok": true, "new_fp": k.new_fingerprint()})
        }
        "fetch_and_ack" => {
            let Some(name) = m["name"].as_str() else {
                return json!({"error": "fetch_and_ack: «name» is missing or not a string"});
            };
            let Some(port) = m["port"].as_u64().and_then(|p| u16::try_from(p).ok()) else {
                return json!({"error": "fetch_and_ack: «port» is missing or not a port number"});
            };
            let Some(now) = m["now"].as_i64() else {
                return json!({"error": "fetch_and_ack: «now» is missing or not a whole number"});
            };
            // Only an announcement verified against a pinned peer is acknowledged.
            let Some(t) = node.peers.lock().unwrap().get(name).cloned() else {
                return json!({"error": format!(
                    "fetch_and_ack: {name:?} is not a pinned peer; no receipt is signed"
                )});
            };
            let reply = match node.talk(port, &json!({"op":"identity"}), Some(name)) {
                Ok(v) => v,
                Err(e) => return json!({"error": format!("the neighbour did not answer: {e}")}),
            };
            if reply.get("announcement").is_none() {
                return json!({"ok": true, "no_announcement": true});
            }
            // NOT `.unwrap()`. An announcement that does not verify is a
            // NORMAL §6.8 state — it must be reported, not bring down the thread.
            // With a panic here the control thread died, and the orchestrator
            // stood waiting until the deadline ran out: the symptom became a
            // timeout instead of the error message that actually explained
            // what was wrong.
            let announcement_json: nettls::announcement::AnnouncementJson =
                match serde_json::from_value(reply["announcement"].clone()) {
                    Ok(v) => v,
                    Err(e) => return json!({"error": format!("invalid announcement: {e}")}),
                };
            let k = match Announcement::from_json(&announcement_json) {
                Ok(v) => v,
                Err(e) => return json!({"error": e.to_string()}),
            };
            if let Err(e) = t.receive(&k, name) {
                return json!({"error": e.to_string()});
            }
            let ack = match Receipt::new(&node.name, name, k.new_fingerprint(), now, &node.seed) {
                Ok(a) => a,
                Err(e) => return json!({"error": format!("fetch_and_ack: {e}")}),
            };
            let receipt = match ack.to_json() {
                Ok(j) => j,
                Err(e) => return json!({"error": e.to_string()}),
            };
            // The neighbour's reply is not copied into ours: it is its text, not ours.
            match node.talk(port, &json!({"op":"ack","receipt": receipt}), Some(name)) {
                Ok(r) if r == json!({"ok": true}) => {}
                Ok(_) => {
                    return json!({"error": format!(
                        "fetch_and_ack: {name:?} did not accept the receipt (its reply is not {{\"ok\": true}})"
                    )});
                }
                Err(e) => return json!({"error": format!("the neighbour did not answer: {e}")}),
            }
            json!({"ok": true, "acked_on": k.new_fingerprint()})
        }
        "roll" => {
            let Some(now) = m["now"].as_i64() else {
                return json!({"error": "roll: «now» is missing or not a whole number"});
            };
            if !node.schedule.lock().unwrap().can_roll(now) {
                return json!({"ok": true, "rolled": false});
            }
            let Some((k, pem, pk)) = node.pending.lock().unwrap().take() else {
                return json!({"ok": true, "rolled": false});
            };
            let old = {
                let mut current = node.current.lock().unwrap();
                let old = current.0.clone();
                // Exactly two are kept: generation N-2 is dropped here.
                *node.previous.lock().unwrap() = Some(current.clone());
                *current = (k.new_fingerprint().to_string(), pem, pk);
                old
            };
            *node.rotations.lock().unwrap() += 1;
            node.schedule.lock().unwrap().rolled(now).unwrap();
            json!({"ok": true, "rolled": true, "old": old})
        }
        // The consumer's MEMORY (§6.11b). `nettls` saves its own material
        // even in Rust, but the ring node mirrors a consuming service here:
        // EVERYTHING goes out, and everything can be put back. Then the test
        // probes the same property in both languages.
        "export" => {
            let hex = |b: &[u8]| krypto::hex::encode(b).map_err(|e| e.to_string());
            let mat = |m: &(String, String, Arc<krypto::SecretBuf>)| -> Result<Value, String> {
                let pkcs8 = m.2.expose(hex)?;
                Ok(json!({"fp": m.0, "cert_pem": m.1, "pkcs8": pkcs8}))
            };
            let current = node.current.lock().unwrap().clone();
            let previous = node.previous.lock().unwrap().clone();
            let pending = node.pending.lock().unwrap().clone();
            let r = node.schedule.lock().unwrap();

            // Every encoding step can fail; the first failure is the reply.
            let state = (|| -> Result<Value, String> {
                let mut peers = serde_json::Map::new();
                for (name, t) in node.peers.lock().unwrap().iter() {
                    let g = t.state().unwrap();
                    let previous = g.previous().map(|x| hex(x.der())).transpose()?;
                    let current = hex(g.current().der())?;
                    let next = g.next().map(|x| hex(x.der())).transpose()?;
                    peers.insert(
                        name.clone(),
                        json!({
                            "previous": previous,
                            "current": current,
                            "next": next,
                        }),
                    );
                }
                let keys: HashMap<String, String> = node
                    .peer_keys
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), hex(v)?)))
                    .collect::<Result<_, String>>()?;
                let pending = match pending.as_ref() {
                    Some((k, pem, pk)) => {
                        let announcement = k.to_json().map_err(|e| e.to_string())?;
                        let pkcs8 = pk.expose(hex)?;
                        Some(json!({
                            "announcement": announcement,
                            "cert_pem": pem,
                            "pkcs8": pkcs8,
                        }))
                    }
                    None => None,
                };

                Ok(json!({
                    "current": mat(&current)?,
                    "previous": previous.as_ref().map(mat).transpose()?,
                    "pending": pending,
                    "peers": peers,
                    "keys": keys,
                    "rotations": *node.rotations.lock().unwrap(),
                    "ackers": node.ackers.lock().unwrap().clone(),
                    "waiting_for": r.waiting_for(),
                    "first_announced": r.first_announced(),
                    "neighbour": node.neighbour_name.lock().unwrap().clone(),
                }))
            })();
            match state {
                Ok(state) => json!({"ok": true, "state": state}),
                Err(e) => json!({"error": e}),
            }
        }
        "import" => {
            let t = &m["state"];
            let text = |v: &Value, what: &str| -> Result<String, String> {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("import: «{what}» is missing or not a string"))
            };
            let unhex = |v: &Value, what: &str| -> Result<Vec<u8>, String> {
                nettls::signature::from_hex(&text(v, what)?)
                    .map_err(|e| format!("import: «{what}»: {e}"))
            };
            // Private keys go straight into locked memory (0.8.3).
            let unhex_key = |v: &Value, what: &str| -> Result<Arc<krypto::SecretBuf>, String> {
                krypto::SecretBuf::from_vec(unhex(v, what)?)
                    .map(Arc::new)
                    .map_err(|e| format!("import: «{what}»: {e}"))
            };
            let mat = |v: &Value, what: &str| -> Result<_, String> {
                Ok((
                    text(&v["fp"], &format!("{what}.fp"))?,
                    text(&v["cert_pem"], &format!("{what}.cert_pem"))?,
                    unhex_key(&v["pkcs8"], &format!("{what}.pkcs8"))?,
                ))
            };
            let generation = |v: &Value, what: &str| -> Result<Generation, String> {
                Generation::from_der(unhex(v, what)?).map_err(|e| format!("import: «{what}»: {e}"))
            };
            let strings = |v: &Value, what: &str| -> Result<Vec<String>, String> {
                v.as_array()
                    .ok_or_else(|| format!("import: «{what}» is missing or not a list"))?
                    .iter()
                    .map(|s| text(s, what))
                    .collect()
            };

            // Every step can fail on what it was given; the first failure is the reply.
            let imported = (|| -> Result<Value, String> {
                *node.current.lock().unwrap() = mat(&t["current"], "current")?;
                *node.previous.lock().unwrap() = t["previous"]
                    .as_object()
                    .map(|_| mat(&t["previous"], "previous"))
                    .transpose()?;

                // The PENDING key pair must be included. Without it a restart
                // between announcement and swap would lose a key the peer has
                // already acked (M-26).
                *node.pending.lock().unwrap() = t["pending"]
                    .as_object()
                    .map(|v| -> Result<_, String> {
                        let announcement_json: nettls::announcement::AnnouncementJson =
                            serde_json::from_value(v["announcement"].clone())
                                .map_err(|e| format!("import: «pending.announcement»: {e}"))?;
                        Ok((
                            Announcement::from_json(&announcement_json)
                                .map_err(|e| format!("import: «pending.announcement»: {e}"))?,
                            text(&v["cert_pem"], "pending.cert_pem")?,
                            unhex_key(&v["pkcs8"], "pending.pkcs8")?,
                        ))
                    })
                    .transpose()?;

                // The peers' generations — the link that keeps a restart from
                // looking like memory loss.
                let mut mp = HashMap::new();
                for (name, d) in t["peers"]
                    .as_object()
                    .ok_or("import: «peers» is missing or not an object")?
                {
                    let g = nettls::generations::Generations::restore(
                        d["previous"]
                            .as_str()
                            .map(|_| generation(&d["previous"], "peers.previous"))
                            .transpose()?,
                        generation(&d["current"], "peers.current")?,
                        d["next"]
                            .as_str()
                            .map(|_| generation(&d["next"], "peers.next"))
                            .transpose()?,
                    )
                    .map_err(|e| format!("import: peer {name:?}: {e}"))?;
                    mp.insert(name.clone(), Trust::from_state(g));
                }
                *node.peers.lock().unwrap() = mp;

                *node.peer_keys.lock().unwrap() = t["keys"]
                    .as_object()
                    .ok_or("import: «keys» is missing or not an object")?
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), unhex(v, "keys")?)))
                    .collect::<Result<_, String>>()?;

                let ackers = strings(&t["ackers"], "ackers")?;
                let mut r = Schedule::new(ackers.clone(), 0);
                if node.pending.lock().unwrap().is_some() {
                    // The promise is binding: the peer may already have acked.
                    r.restore_announced(
                        strings(&t["waiting_for"], "waiting_for")?,
                        t["first_announced"].as_i64().unwrap_or(0),
                    );
                }
                *node.schedule.lock().unwrap() = r;
                *node.ackers.lock().unwrap() = ackers;
                *node.rotations.lock().unwrap() = t["rotations"]
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or("import: «rotations» is missing or not a whole number")?;
                // Without the neighbour's name the marker path could not pin after a restart.
                *node.neighbour_name.lock().unwrap() = match &t["neighbour"] {
                    Value::Null => None,
                    v => Some(text(v, "neighbour")?),
                };

                let fp = node.current.lock().unwrap().0.clone();
                Ok(json!({"ok": true, "fp": fp}))
            })();
            imported.unwrap_or_else(|e| json!({"error": e}))
        }
        // A hostile announcement fed straight into the receive path (§6.15b).
        //
        // Two things must hold, and the second is the important one: the
        // message must be rejected, AND the state must be unchanged afterwards.
        // A receiver that rejects, but manages to write half the message into
        // `Generations` first, has not rejected it — it has merely refrained
        // from saying yes.
        "inject" => {
            let Some(name) = m["name"].as_str() else {
                return json!({"error": "inject: «name» is missing or not a string"});
            };
            let before = state_of(node, name);
            let err = (|| -> Result<(), String> {
                let announcement_json: nettls::announcement::AnnouncementJson =
                    serde_json::from_value(m["announcement"].clone())
                        .map_err(|e| format!("serde: {e}"))?;
                let k = Announcement::from_json(&announcement_json).map_err(|e| e.to_string())?;
                let mp = node.peers.lock().unwrap();
                let t = mp.get(name).ok_or("unknown peer")?;
                t.receive(&k, name).map(|_| ()).map_err(|e| e.to_string())
            })()
            .err();
            let after_state = state_of(node, name);
            json!({
                "ok": true,
                "rejected": err.is_some(),
                // NOT "error": the control channel reads that field as a
                // protocol failure. Here a rejection is exactly what should
                // happen.
                "rejected_reason": err,
                "unchanged": before == after_state,
            })
        }
        "marker" => {
            // NOT `.unwrap()`. A neighbour that does not answer — because it
            // was killed, is restarting, or pins us on a certificate we no
            // longer have — is a COMPLETELY NORMAL §6.8 state, and must be
            // reported as an
            // err.
            //
            // With `.unwrap()` the control thread panicked instead, and no
            // reply was ever written to stdout: the orchestrator stood waiting
            // forever. A hanging test does not say what is wrong; it only says
            // something is. The Python node returns an error in the same
            // situation.
            let Some(skip) = m["skip"].as_i64().filter(|s| (0..=MAX_SKIP).contains(s)) else {
                return json!({"error": format!(
                    "marker: «skip» must be a whole number from 0 to {MAX_SKIP}"
                )});
            };
            let Some(nb) = node.neighbour_name.lock().unwrap().clone() else {
                return json!({"error": "no pinned neighbour to pass the marker to"});
            };
            match node.talk(
                node.neighbour_port,
                &json!({"op":"marker","marker":m["marker"],"skip":skip}),
                Some(&nb),
            ) {
                Ok(reply) if reply.get("error").is_some() => json!({"error": reply["error"]}),
                Ok(reply) => json!({"ok": true, "marker": reply["marker"]}),
                Err(e) => json!({"error": format!("could not pass the marker on: {e}")}),
            }
        }
        "status" => {
            let mp: HashMap<String, Value> = node
                .peers
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| {
                    let g = v.state().unwrap();
                    (
                        k.clone(),
                        json!({
                            "current": g.current().fingerprint(),
                            "previous": g.previous().map(|x| x.fingerprint().to_string()),
                            "next": g.next().map(|x| x.fingerprint().to_string()),
                        }),
                    )
                })
                .collect();
            json!({
                "ok": true,
                "fp": node.current.lock().unwrap().0,
                "rotations": *node.rotations.lock().unwrap(),
                "peers": mp,
            })
        }
        "stop" => {
            println!("{}", json!({"ok": true}));
            std::process::exit(0);
        }
        op => json!({"error": format!("unknown control op: {op}")}),
    }
}

fn main() {
    nettls::install_crypto_provider();
    let a: Vec<String> = std::env::args().collect();
    let node = Arc::new(Node::new(
        &a[1],
        a[2].parse().unwrap(),
        a[3].parse().unwrap(),
        nettls::signature::from_hex(&a[4]).unwrap(),
    ));

    // Control on stdin.
    {
        let node = node.clone();
        std::thread::spawn(move || {
            let mut input = std::io::stdin().lock();
            loop {
                let mut line = Vec::new();
                match (&mut input)
                    .take(MAX_CONTROL_LINE as u64 + 1)
                    .read_until(b'\n', &mut line)
                {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let reply = if line.len() > MAX_CONTROL_LINE {
                    // The rest of the line is skipped, so it is not read as the next command.
                    if !line.ends_with(b"\n") {
                        let _ = input.skip_until(b'\n');
                    }
                    json!({"error": format!(
                        "the control line is longer than {MAX_CONTROL_LINE} bytes"
                    )})
                } else if line.trim_ascii().is_empty() {
                    continue;
                } else {
                    match serde_json::from_slice::<Value>(&line) {
                        Ok(m) => control(&node, &m),
                        Err(e) => json!({"error": format!("the control line is not JSON: {e}")}),
                    }
                };
                println!("{reply}");
                let _ = std::io::stdout().flush();
            }
        });
    }

    let listener = TcpListener::bind(("127.0.0.1", node.port)).unwrap();
    println!(
        "{}",
        json!({"ready": node.name, "fp": node.current.lock().unwrap().0})
    );
    let _ = std::io::stdout().flush();

    // Connections being handled now; one more than the bound is closed at once.
    let active = Arc::new(AtomicUsize::new(0));
    for tcp in listener.incoming() {
        let Ok(mut tcp) = tcp else { continue };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let node = node.clone();
        let active = active.clone();
        std::thread::spawn(move || {
            (|| {
                if tcp.set_read_timeout(Some(IO_TIMEOUT)).is_err()
                    || tcp.set_write_timeout(Some(IO_TIMEOUT)).is_err()
                {
                    return;
                }
                let Ok(cfg) = node.server_config() else {
                    return;
                };
                let Ok(mut conn) = rustls::ServerConnection::new(cfg) else {
                    return;
                };
                let mut s = rustls::Stream::new(&mut conn, &mut tcp);
                let mut line = String::new();
                let read = BufReader::new(&mut s)
                    .take(MAX_NETWORK_LINE as u64 + 1)
                    .read_line(&mut line);
                if read.is_err() || line.is_empty() || line.len() > MAX_NETWORK_LINE {
                    return;
                }
                let Ok(m) = serde_json::from_str::<Value>(&line) else {
                    return;
                };
                let reply = node.handle(&m);
                let _ = s.write_all(format!("{reply}\n").as_bytes());
                let _ = s.flush();
            })();
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}
