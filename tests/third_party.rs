// SPDX-License-Identifier: MIT OR Apache-2.0
//! Third-party guard.
//!
//! `THIRD_PARTY_LICENSES.md` lists every package in `Cargo.lock` other than the
//! workspace's own two, and every package pinned in
//! `nettls-py/requirements-ci.txt`, each with the license it declares. A
//! dependency added without a row, a row left behind for a dependency that is
//! gone, and a row without a license all fail here. The published crate carries
//! neither `nettls-py/` nor the workspace's whole `Cargo.lock`, so the two tests
//! that need them skip there.

use std::collections::BTreeSet;
use std::fs;

const DOCUMENT: &str = "THIRD_PARTY_LICENSES.md";
const RUST_SECTION: &str = "Rust crates";
const PYTHON_SECTION: &str = "Python packages";
const WORKSPACE_PACKAGES: [&str; 2] = ["nettls", "nettls-py"];

fn read(rel: &str) -> String {
    fs::read_to_string(format!("{}/{rel}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// The table rows, as cells, under `## <title>` in the document; the header
/// row and the separator row are left out.
fn rows(title: &str) -> Vec<Vec<String>> {
    let text = read(DOCUMENT);
    let body = text
        .split("\n## ")
        .find_map(|part| part.strip_prefix(&format!("{title}\n")))
        .unwrap_or_else(|| panic!("{DOCUMENT} has no section '## {title}'"));
    let rows: Vec<Vec<String>> = body
        .lines()
        .filter(|line| line.starts_with('|'))
        .filter(|line| !line.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ')))
        .map(|line| {
            line.trim()
                .trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_string())
                .collect()
        })
        .skip(1)
        .collect();
    assert!(
        !rows.is_empty(),
        "the section '## {title}' in {DOCUMENT} has no table rows"
    );
    rows
}

/// The first cell of each row: the package name.
fn listed(title: &str) -> BTreeSet<String> {
    rows(title).into_iter().map(|row| row[0].clone()).collect()
}

/// Every package name in `Cargo.lock`, the workspace's own excluded.
fn lock_packages() -> BTreeSet<String> {
    let names: BTreeSet<String> = read("Cargo.lock")
        .lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .filter(|name| !WORKSPACE_PACKAGES.contains(name))
        .map(str::to_string)
        .collect();
    // Positive control: an empty set would let the comparisons pass for nothing.
    assert!(
        names.contains("rustls"),
        "Cargo.lock does not look as expected"
    );
    names
}

/// A Python package name as pip compares it: case, and runs of `-`, `_` and
/// `.`, do not matter.
fn normalized(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// Every package pinned in `nettls-py/requirements-ci.txt`, normalized.
fn pinned_python_packages() -> BTreeSet<String> {
    let names: BTreeSet<String> = read("nettls-py/requirements-ci.txt")
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(|line| {
            let end = line
                .find(|c: char| "=<>!~[; ".contains(c))
                .unwrap_or(line.len());
            normalized(&line[..end])
        })
        .collect();
    assert!(
        names.contains("pytest"),
        "nettls-py/requirements-ci.txt does not look as expected"
    );
    names
}

/// True in the published crate, which does not carry `nettls-py/` and whose
/// `Cargo.lock` holds only the library's packages; the caller then skips, and
/// this prints why. Only "not found" counts: any other error fails the test,
/// so a checkout never skips.
fn skip_without_binding() -> bool {
    let dir = format!("{}/nettls-py", env!("CARGO_MANIFEST_DIR"));
    match fs::metadata(&dir) {
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: this is the published crate, which does not carry nettls-py/");
            true
        }
        Err(e) => panic!("cannot tell whether {dir} is there: {e}"),
    }
}

#[test]
fn every_crate_in_the_lock_file_is_listed() {
    let listed = listed(RUST_SECTION);
    let missing: Vec<String> = lock_packages().difference(&listed).cloned().collect();
    assert!(
        missing.is_empty(),
        "in Cargo.lock but not in {DOCUMENT} under '## {RUST_SECTION}': {missing:?} — \
         give each a row with the license it declares"
    );
}

#[test]
fn every_listed_crate_is_in_the_lock_file() {
    if skip_without_binding() {
        return;
    }
    let in_lock = lock_packages();
    let stale: Vec<String> = listed(RUST_SECTION).difference(&in_lock).cloned().collect();
    assert!(
        stale.is_empty(),
        "in {DOCUMENT} under '## {RUST_SECTION}' but not in Cargo.lock: {stale:?}"
    );
}

#[test]
fn the_python_table_lists_exactly_the_pinned_packages() {
    if skip_without_binding() {
        return;
    }
    let listed: BTreeSet<String> = listed(PYTHON_SECTION)
        .iter()
        .map(|name| normalized(name))
        .collect();
    let pinned = pinned_python_packages();
    let missing: Vec<&String> = pinned.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "pinned in nettls-py/requirements-ci.txt but not in {DOCUMENT} under \
         '## {PYTHON_SECTION}': {missing:?}"
    );
    let stale: Vec<&String> = listed.difference(&pinned).collect();
    assert!(
        stale.is_empty(),
        "in {DOCUMENT} under '## {PYTHON_SECTION}' but not pinned in \
         nettls-py/requirements-ci.txt: {stale:?}"
    );
}

#[test]
fn every_row_names_a_license() {
    for title in [RUST_SECTION, PYTHON_SECTION] {
        for row in rows(title) {
            assert!(
                row.len() == 3,
                "a row under '## {title}' in {DOCUMENT} does not have three cells: {row:?}"
            );
            assert!(
                !row[1].is_empty(),
                "{} under '## {title}' in {DOCUMENT} has no license",
                row[0]
            );
        }
    }
}
