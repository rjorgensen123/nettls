// SPDX-License-Identifier: MIT OR Apache-2.0
//! Version guard.
//!
//! The version is written in two places: `Cargo.toml`, and `nettls-py/Cargo.toml`,
//! which the Python package takes its version from;
//! `the_binding_has_the_crates_version` holds the second to the first. The
//! crate's `VERSION` constant derives from `Cargo.toml`, and
//! `version_constant_mirrors_cargo_toml` checks that it does; `nettls_py` gives
//! Python that same constant as `__version__`. Until 0.8.6 the version stood in
//! three files kept in step by tests.
//!
//! The changelog can drift too. A version can be cut without anyone writing
//! down what changed in it, and `changelog_has_an_entry_for_the_current_version`
//! catches that.

#[test]
fn changelog_has_an_entry_for_the_current_version() {
    let changelog = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/CHANGELOG.md"))
        .expect("CHANGELOG.md must exist");
    let heading = format!("## [{}]", env!("CARGO_PKG_VERSION"));
    assert!(
        changelog.contains(&heading),
        "CHANGELOG.md has no '{heading}' entry — a cut version without a changelog entry \
         is a version nobody can migrate to"
    );
}

/// 0.8.2: the `VERSION` constant must mirror Cargo.toml (the anchor that says
/// which feature set is active).
#[test]
fn version_constant_mirrors_cargo_toml() {
    assert_eq!(nettls::VERSION, env!("CARGO_PKG_VERSION"));
}

/// The `version` in the `[package]` table of a Cargo manifest.
fn package_version(manifest: &str) -> Option<&str> {
    let mut in_package = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_package = line == "[package]";
        } else if in_package
            && let Some((key, value)) = line.split_once('=')
            && key.trim() == "version"
        {
            return value.trim().strip_prefix('"')?.strip_suffix('"');
        }
    }
    None
}

/// True in the published crate, which does not carry `nettls-py/`; the caller
/// then skips, and this prints why. Only "not found" counts: any other error
/// fails the test, so a checkout never skips.
fn skip_without_binding() -> bool {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/nettls-py");
    match std::fs::metadata(dir) {
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: this is the published crate, which does not carry nettls-py/");
            true
        }
        Err(e) => panic!("cannot tell whether {dir} is there: {e}"),
    }
}

/// `nettls-py/Cargo.toml` writes the version a second time, and the Python
/// package takes its version from there, so it must be the crate's.
#[test]
fn the_binding_has_the_crates_version() {
    if skip_without_binding() {
        return;
    }
    let manifest =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/nettls-py/Cargo.toml"))
            .expect("nettls-py/Cargo.toml must exist");
    let binding = package_version(&manifest)
        .expect("nettls-py/Cargo.toml must have a quoted version in [package]");
    assert_eq!(
        binding,
        env!("CARGO_PKG_VERSION"),
        "nettls-py/Cargo.toml has version {binding}, Cargo.toml has {} — the Python \
         package would carry another version than the crate",
        env!("CARGO_PKG_VERSION")
    );
}
