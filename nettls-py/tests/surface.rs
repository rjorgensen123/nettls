// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Python API is the Rust API (0.11.0): the same names in the same places,
//! both ways.
//!
//! The Rust side is read from the crate's source: the root's `pub mod`,
//! `pub const` and `pub use`, the `pub` items of the public modules, the
//! `pub fn` and `pub` fields of each public type, and the variants of its
//! enums. The Python side is what `nettls_py` shows under the Python that
//! `PYO3_PYTHON` names, with `nettls_py` installed (`maturin develop`). A name
//! on one side only fails the test, unless it is listed below with its reason.
//!
//! The mapping: `Mode::Rolling` is `Mode.Rolling`, `Schedule::new` is
//! `Schedule.new`, a field is an attribute, and each `TlsError` variant is an
//! exception, `TlsError::Pem` being `PemError` (also as `error.PemError`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Names only Rust has, and why.
const RUST_ONLY: &[(&str, &str)] = &[
    (
        "rustls",
        "the rustls crate itself, re-exported for Rust consumers",
    ),
    (
        "provider.provider",
        "a rustls value; every config the crate builds already uses it",
    ),
    (
        "aegis.suite",
        "a rustls value; the transport policy is what picks the suite",
    ),
    (
        "TlsMaterial.certified_key",
        "a rustls value; server_config is what Python uses",
    ),
    (
        "material.TlsMaterial.certified_key",
        "a rustls value; server_config is what Python uses",
    ),
    (
        "announcer.Pending",
        "made and taken only inside the crate; no public function gives one out",
    ),
    ("announcer.Pending.announcement", "see announcer.Pending"),
    ("announcer.Pending.new_cert_pem", "see announcer.Pending"),
    ("announcer.Pending.new_pkcs8", "see announcer.Pending"),
    ("pin.classify", CLASSIFY),
    ("pin.Rejection", CLASSIFY),
    ("pin.Rejection.Untrusted", CLASSIFY),
    ("pin.Rejection.Expired", CLASSIFY),
    ("pin.Rejection.NotYetValid", CLASSIFY),
    ("pin.Rejection.Other", CLASSIFY),
];

const CLASSIFY: &str =
    "reads a Rust error; Python gets the same answer as the exceptions in stream";

const STREAM: &str =
    "the TLS connection over a Python socket: Rust consumers drive rustls themselves";
const ALG: &str = "krypto::Alg, which lockbox, envelope and capability take";
const SERDE: &str = "what serde_json does with the type in Rust";

/// Names only Python has, and why.
const PYTHON_ONLY: &[(&str, &str)] = &[
    (
        "nettls_py",
        "the compiled module itself, as maturin packages it",
    ),
    ("Alg", ALG),
    ("Alg.Aegis256", ALG),
    ("Alg.XChaCha20Poly1305", ALG),
    ("Alg.Aes256Gcm", ALG),
    ("stream", STREAM),
    ("stream.MAX_READ", STREAM),
    ("stream.ClientConfig", STREAM),
    ("stream.ServerConfig", STREAM),
    ("stream.Stream", STREAM),
    ("stream.Stream.connect", STREAM),
    ("stream.Stream.accept", STREAM),
    ("stream.Stream.read", STREAM),
    ("stream.Stream.write", STREAM),
    ("stream.Stream.flush", STREAM),
    ("stream.Stream.close", STREAM),
    ("stream.Stream.peer_fingerprint", STREAM),
    ("stream.Stream.alpn_protocol", STREAM),
    ("stream.UntrustedPeerError", STREAM),
    ("stream.CertificateExpiredError", STREAM),
    ("stream.CertificateNotYetValidError", STREAM),
    ("announcement.AnnouncementJson.dumps", SERDE),
    ("announcement.AnnouncementJson.loads", SERDE),
    ("announcement.ReceiptJson.dumps", SERDE),
    ("announcement.ReceiptJson.loads", SERDE),
    ("announcement.IdentityJson.dumps", SERDE),
    ("announcement.IdentityJson.loads", SERDE),
    ("approval.ApprovalJson.dumps", SERDE),
    ("approval.ApprovalJson.loads", SERDE),
    ("capability.SupportStatement.dumps", SERDE),
    ("capability.SupportStatement.loads", SERDE),
    ("status.PeerReport.dumps", SERDE),
    ("status.IdentityReport.dumps", SERDE),
    ("status.RotationReport.dumps", SERDE),
    ("status.Report.dumps", SERDE),
    ("status.Summary.dumps", SERDE),
];

/// What `nettls_py` shows: every public name, the submodules' names, and the
/// public members of each class that is not an exception.
const PYTHON_SURFACE: &str = r#"
import types
import nettls_py

out = set()

def walk(obj, prefix):
    for name in dir(obj):
        if name.startswith("_"):
            continue
        value = getattr(obj, name)
        out.add(prefix + name)
        if isinstance(value, types.ModuleType):
            if not prefix and name != "nettls_py" and value.__name__ == "nettls_py." + name:
                walk(value, name + ".")
        elif isinstance(value, type) and not issubclass(value, BaseException):
            out.update(prefix + name + "." + m for m in dir(value) if not m.startswith("_"))

walk(nettls_py, "")
print("\n".join(sorted(out)))
"#;

fn ident(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// The crate's public names, written as Python paths.
fn rust_surface() -> BTreeSet<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../src");
    let mut names = BTreeSet::new();

    // The root: public modules, constants, and re-exports (also those over
    // several lines).
    let lib = fs::read_to_string(src.join("lib.rs")).expect("cannot read src/lib.rs");
    let mut modules = Vec::new();
    let mut root = BTreeSet::new();
    let mut pending_use: Option<String> = None;
    for line in lib.lines() {
        if let Some(acc) = pending_use.as_mut() {
            acc.push_str(line.trim());
            acc.push(' ');
            if !line.trim_end().ends_with(';') {
                continue;
            }
        } else if let Some(rest) = line.strip_prefix("pub mod ") {
            modules.push(ident(rest));
            continue;
        } else if let Some(rest) = line.strip_prefix("pub const ") {
            root.insert(ident(rest));
            continue;
        } else if let Some(rest) = line.strip_prefix("pub use ") {
            pending_use = Some(format!("{rest} "));
            if !rest.trim_end().ends_with(';') {
                continue;
            }
        } else {
            continue;
        }
        let used = pending_use.take().unwrap();
        match (used.find('{'), used.find('}')) {
            (Some(open), Some(close)) => root.extend(
                used[open + 1..close]
                    .split(',')
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(String::from),
            ),
            _ => {
                root.insert(ident(used.trim().rsplit("::").next().unwrap()));
            }
        }
    }
    names.extend(modules.iter().cloned());
    names.extend(root.iter().cloned());

    // Every file: the public items of public modules, and for each type its
    // `pub fn`, `pub` fields and enum variants.
    let mut places: BTreeMap<String, Vec<String>> = BTreeMap::new(); // type -> prefixes
    let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new(); // type -> members
    let mut variants: BTreeMap<String, Vec<String>> = BTreeMap::new(); // enum -> variants
    let mut files: Vec<_> = fs::read_dir(&src)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort();
    for path in files {
        let module = path.file_stem().unwrap().to_string_lossy().into_owned();
        if module == "lib" {
            continue;
        }
        let public = modules.contains(&module);
        let text = fs::read_to_string(&path).unwrap();
        let mut in_impl: Option<String> = None;
        let mut in_enum: Option<String> = None;
        let mut in_struct: Option<String> = None;
        for line in text.lines() {
            if line == "}" {
                in_impl = None;
                in_enum = None;
                in_struct = None;
                continue;
            }
            if let Some(ty) = &in_impl {
                if let Some(rest) = line.strip_prefix("    pub fn ") {
                    members.entry(ty.clone()).or_default().insert(ident(rest));
                }
                continue;
            }
            if let Some(ty) = &in_struct {
                if let Some(rest) = line.strip_prefix("    pub ")
                    && rest.contains(':')
                    && !rest.starts_with("fn ")
                {
                    members.entry(ty.clone()).or_default().insert(ident(rest));
                }
                continue;
            }
            if let Some(ty) = &in_enum {
                if let Some(rest) = line.strip_prefix("    ")
                    && rest.starts_with(|c: char| c.is_ascii_uppercase())
                {
                    variants.entry(ty.clone()).or_default().push(ident(rest));
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("impl") {
                if line.ends_with('{') && !line.contains(" for ") {
                    let rest = match rest.strip_prefix('<') {
                        Some(r) => &r[r.find('>').unwrap() + 1..],
                        None => rest,
                    };
                    in_impl = Some(ident(rest.trim_start()));
                }
                continue;
            }
            for kind in ["pub fn ", "pub const ", "pub struct ", "pub enum "] {
                let Some(rest) = line.strip_prefix(kind) else {
                    continue;
                };
                let name = ident(rest);
                if public {
                    names.insert(format!("{module}.{name}"));
                }
                if kind == "pub struct " || kind == "pub enum " {
                    let mut at = Vec::new();
                    if root.contains(&name) {
                        at.push(String::new());
                    }
                    if public {
                        at.push(format!("{module}."));
                    }
                    places.insert(name.clone(), at);
                    if line.ends_with('{') {
                        if kind == "pub enum " {
                            in_enum = Some(name);
                        } else {
                            in_struct = Some(name);
                        }
                    }
                }
            }
        }
    }

    for (ty, at) in &places {
        for prefix in at {
            for m in members.get(ty).into_iter().flatten() {
                names.insert(format!("{prefix}{ty}.{m}"));
            }
            for v in variants.get(ty).into_iter().flatten() {
                if ty == "TlsError" {
                    names.insert(format!("{prefix}{v}Error"));
                } else {
                    names.insert(format!("{prefix}{ty}.{v}"));
                }
            }
        }
    }
    names
}

fn python_surface() -> BTreeSet<String> {
    let python = std::env::var_os("PYO3_PYTHON").unwrap_or_else(|| "python3".into());
    let out = Command::new(&python)
        .args(["-I", "-c", PYTHON_SURFACE])
        .output()
        .unwrap_or_else(|e| panic!("cannot run {python:?}: {e}"));
    assert!(
        out.status.success(),
        "PYO3_PYTHON must name a Python with nettls_py installed (maturin develop):\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn the_python_api_is_the_rust_api() {
    let mut rust = rust_surface();
    assert!(
        rust.len() >= 300,
        "the Rust side found suspiciously few names ({}): is the reader broken?",
        rust.len()
    );
    for (name, _why) in RUST_ONLY {
        assert!(
            rust.remove(*name),
            "{name} is in RUST_ONLY but not in nettls"
        );
    }
    let mut python = python_surface();
    for (name, _why) in PYTHON_ONLY {
        assert!(
            python.remove(*name),
            "{name} is in PYTHON_ONLY but not in nettls_py"
        );
    }
    let only_rust: Vec<_> = rust.difference(&python).collect();
    let only_python: Vec<_> = python.difference(&rust).collect();
    assert!(
        only_rust.is_empty() && only_python.is_empty(),
        "the APIs differ.\nOnly in Rust (add to nettls-py, or to RUST_ONLY with a reason): \
         {only_rust:?}\nOnly in Python (add to nettls, or to PYTHON_ONLY with a reason): \
         {only_python:?}"
    );
}
