// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal PEM encoding (DER → PEM) and safe writing to disk.
//!
//! We *read* PEM with `rustls-pki-types` (its `pem` feature, 0.8.1); writing
//! lives here. The base64 body is `krypto::base64` (0.8.1: own variants go
//! away once krypto has the building block).
//!
//! The module also owns the rule that matters when private keys hit disk:
//! **write atomically, and never leave a file more open than it should be.**

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::TlsError;

/// The longest label [`encode`] takes, in bytes: the characters a label may
/// hold are ASCII *(0.12.0)*.
const MAX_LABEL_LEN: usize = 64;

/// Encodes DER as a PEM block with the given label, 64 chars per line (RFC 7468).
///
/// **Public since 0.8.1:** PEM is TLS domain, so building it lives
/// here — consumers that used to build PEM by hand use this instead. The
/// base64 body is the canonical `krypto::base64`. The intermediate is
/// zeroized: the DER may be a private key. (The returned buffer is the
/// caller's to protect — for a key, `save_pem` holds it in a `SecretBuf`.)
///
/// Fails with [`TlsError::Encode`] when the DER is over krypto's size limit,
/// or the memory for the base64 or the PEM text could not be reserved
/// *(0.12.0)*.
///
/// The label is 1 to 64 characters: capital letters `A`–`Z`, digits and
/// single spaces, with no space first or last. Any other label is
/// [`TlsError::Params`], refused before the DER is encoded *(0.12.0)*.
pub fn encode(label: &str, der: &[u8]) -> Result<Vec<u8>, TlsError> {
    check_label(label)?;
    // Wiped when it goes out of scope, on the error path too.
    let b64 = Zeroizing::new(
        krypto::base64::encode(der)
            .map_err(|e| TlsError::Encode(format!("the DER as base64: {e}")))?
            .into_bytes(),
    );

    // Exactly what is written below: the two label lines are 32 bytes apart
    // from the labels, and every body line ends in a newline. Saturating, so a
    // size that does not fit fails the reservation instead of wrapping.
    let len = b64
        .len()
        .saturating_add(b64.len().div_ceil(64))
        .saturating_add(label.len().saturating_mul(2))
        .saturating_add(32);
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| TlsError::Encode(format!("the DER as PEM: cannot reserve {len} bytes")))?;
    out.extend_from_slice(b"-----BEGIN ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");
    for line in b64.chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");

    Ok(out)
}

/// Refuses a PEM label that is empty, over [`MAX_LABEL_LEN`] bytes, or
/// not capital letters, digits and single spaces with no space first or last
/// *(0.12.0)*. The length is checked before the characters are looked at.
fn check_label(label: &str) -> Result<(), TlsError> {
    if label.is_empty() {
        return Err(TlsError::Params(
            "the PEM label is empty; a label is 1 to 64 characters".to_string(),
        ));
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(TlsError::Params(format!(
            "the PEM label is {} bytes, over the bound of {MAX_LABEL_LEN} bytes",
            label.len()
        )));
    }
    if let Some(c) = label
        .chars()
        .find(|c| !(c.is_ascii_uppercase() || c.is_ascii_digit() || *c == ' '))
    {
        return Err(TlsError::Params(format!(
            "the PEM label {label:?} has the character {c:?}; a label is capital letters A to Z, \
             digits and single spaces"
        )));
    }
    if label.starts_with(' ') || label.ends_with(' ') || label.contains("  ") {
        return Err(TlsError::Params(format!(
            "the PEM label {label:?} has a space first, last or beside another space; spaces in a \
             label are single and between other characters"
        )));
    }
    Ok(())
}

/// Writes `bytes` to `path` atomically, with `mode`.
///
/// The temp file is created 0600 and only if nothing is there; a leftover or a
/// symlink in its place is removed first. `mode` is set before `rename`, the temp
/// file is removed on error, and the directory is synced afterwards. If only that
/// sync fails, the error says the file is in place *(0.12.0)*. On non-unix
/// `mode` is ignored.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), TlsError> {
    let tmp = temp_path(path);
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(TlsError::io(&tmp, e)),
    }
    let written = write_new(&tmp, bytes, mode).and_then(|()| {
        fs::rename(&tmp, path).map_err(|e| TlsError::io(path, e))?;
        sync_dir(path, &format!("{} is in place", path.display()))
    });
    if written.is_err() {
        // Best effort: the next write removes it anyway.
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// The temp file a write to `path` goes through: `path` with the extension
/// `tmp`, beside it *(0.12.0)*.
pub(crate) fn temp_path(path: &Path) -> PathBuf {
    path.with_extension("tmp")
}

/// Writes a certificate and its key as a pair: both temp files are written in
/// full, each with its mode and synced, and the directory is synced, before
/// either is renamed into place *(0.12.0)*: the temp files are then on disk
/// under their names. Then the certificate is renamed and the directory synced, then
/// the key is renamed and the directory synced again. The certificate's rename
/// is on disk before the key's is asked for, so a crash cannot keep the key's
/// rename without the certificate's.
///
/// A failure before the first rename, or of the first rename, removes both temp
/// files and leaves the stored pair as it was. If the sync after the first
/// rename or the key's rename fails, the key's temp file is left for
/// `material::settle_interrupted_save` to put in place, and the error says so.
/// On non-unix the modes are ignored.
pub(crate) fn write_pair(
    cert: &Path,
    cert_bytes: &[u8],
    cert_mode: u32,
    key: &Path,
    key_bytes: &[u8],
    key_mode: u32,
) -> Result<(), TlsError> {
    let cert_tmp = temp_path(cert);
    let key_tmp = temp_path(key);
    let staged = write_new(&cert_tmp, cert_bytes, cert_mode)
        .and_then(|()| write_new(&key_tmp, key_bytes, key_mode))
        .and_then(|()| {
            sync_parent(cert, |e| {
                format!(
                    "{e}; the temp files are written, but the directory could not be synced, \
                     so nothing was put in place"
                )
            })
        })
        .and_then(|()| fs::rename(&cert_tmp, cert).map_err(|e| TlsError::io(cert, e)));
    if let Err(e) = staged {
        // Key first: a crash in between then leaves the temp certificate, which
        // marks the pair as untouched.
        remove_quietly(&key_tmp);
        remove_quietly(&cert_tmp);
        return Err(e);
    }
    let key_left = || {
        format!(
            "its key was left in {}, which the next save, or the next load through \
             CertSource::auto or an Announcer, puts in place",
            key_tmp.display()
        )
    };
    sync_dir(
        cert,
        &format!("the new certificate is in {}", cert.display()),
    )
    .map_err(|e| match e {
        TlsError::Io { path, detail } => TlsError::Io {
            path,
            detail: format!("{detail}; {}", key_left()),
        },
        other => other,
    })?;
    fs::rename(&key_tmp, key).map_err(|e| TlsError::Io {
        path: Some(key.to_path_buf()),
        detail: format!(
            "{e}; the new certificate is in {}, and {}",
            cert.display(),
            key_left()
        ),
    })?;
    sync_dir(
        key,
        &format!("{} and {} are in place", cert.display(), key.display()),
    )
}

/// Removes a temp file after a failed write of the pair. Best effort: what is
/// left is settled before the next save or load of the pair.
fn remove_quietly(tmp: &Path) {
    let _ = fs::remove_file(tmp);
}

/// What is at the temp path `path` *(0.12.0)*: `None` when nothing is there, or
/// when a symbolic link was, which is removed without being followed; its
/// metadata when it is a regular file. Anything else, and a link that cannot be
/// removed, is an error that names it.
pub(crate) fn regular_temp_file(path: &Path) -> Result<Option<fs::Metadata>, TlsError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(TlsError::io(path, e)),
    };
    if meta.file_type().is_symlink() {
        fs::remove_file(path).map_err(|e| TlsError::Io {
            path: Some(path.to_path_buf()),
            detail: format!(
                "{e}; it is a symbolic link where a temp file goes, and could not be removed"
            ),
        })?;
        return Ok(None);
    }
    if !meta.is_file() {
        return Err(TlsError::Io {
            path: Some(path.to_path_buf()),
            detail: "is there but is not a regular file, so it is not a temp file nettls wrote; \
                     it was left as it is"
                .to_string(),
        });
    }
    Ok(Some(meta))
}

/// Removes the temp file `path` an interrupted save left *(0.12.0)*. Nothing
/// there is fine; a file that cannot be removed is an error that names it.
pub(crate) fn remove_temp(path: &Path) -> Result<(), TlsError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(TlsError::Io {
            path: Some(path.to_path_buf()),
            detail: format!("{e}; it was left by an interrupted save and could not be removed"),
        }),
    }
}

/// Reads the temp file `path`, which [`regular_temp_file`] found as `seen`,
/// straight into locked memory: it may hold a private key *(0.12.0)*. A file
/// that is no longer the one that was looked at, such as a symbolic link put
/// in its place, is an error and is not read; that comparison is made on unix.
/// A file over `material::MAX_MATERIAL_LEN` (1 MiB) is an error and is not
/// read, by the rule of [`read_capped_secret`].
pub(crate) fn read_temp(path: &Path, seen: &fs::Metadata) -> Result<krypto::SecretBuf, TlsError> {
    let unreadable = |e: std::io::Error| TlsError::Io {
        path: Some(path.to_path_buf()),
        detail: format!("{e}; it was left by an interrupted save and could not be read"),
    };
    let mut f = fs::File::open(path).map_err(unreadable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = f.metadata().map_err(unreadable)?;
        if opened.dev() != seen.dev() || opened.ino() != seen.ino() {
            return Err(TlsError::Io {
                path: Some(path.to_path_buf()),
                detail: "was replaced between being looked at and being opened; it was not read"
                    .to_string(),
            });
        }
    }
    #[cfg(not(unix))]
    let _ = seen;
    let bound = crate::material::MAX_MATERIAL_LEN;
    read_capped_secret(&mut f, bound, unreadable, |len| {
        over_bound(
            path,
            "the temp key file an interrupted save left",
            bound,
            len,
        )
    })
}

/// Reads the open file `f` whole *(0.12.0)*. A file longer than `bound` bytes
/// is refused before a byte is read, and one that grows past `bound` while it
/// is read is refused once `bound + 1` bytes have come, so no more than that is
/// ever read. `too_large` makes the error for a refusal from the length the
/// file had, or `None` when it grew; `io` makes the error for a failed read.
pub(crate) fn read_capped(
    f: &mut fs::File,
    bound: usize,
    io: impl Fn(std::io::Error) -> TlsError,
    too_large: impl FnOnce(Option<u64>) -> TlsError,
) -> Result<Vec<u8>, TlsError> {
    let len = f.metadata().map_err(&io)?.len();
    if len > to_u64(bound) {
        return Err(too_large(Some(len)));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(usize::try_from(len).unwrap_or(bound).saturating_add(1))
        .map_err(|_| io(std::io::ErrorKind::OutOfMemory.into()))?;
    f.take(to_u64(bound).saturating_add(1))
        .read_to_end(&mut out)
        .map_err(&io)?;
    if out.len() > bound {
        return Err(too_large(None));
    }
    Ok(out)
}

/// [`read_capped`] for a file that may hold a private key: what is read goes
/// into locked memory *(0.12.0)*. The buffer it is read into is made at
/// `bound + 1` bytes before the first byte is read, so it is never reallocated
/// while it holds key bytes, and it is wiped on every way out; `secret::hold`
/// moves the bytes read into locked memory.
pub(crate) fn read_capped_secret(
    f: &mut fs::File,
    bound: usize,
    io: impl Fn(std::io::Error) -> TlsError,
    too_large: impl FnOnce(Option<u64>) -> TlsError,
) -> Result<krypto::SecretBuf, TlsError> {
    let len = f.metadata().map_err(&io)?.len();
    if len > to_u64(bound) {
        return Err(too_large(Some(len)));
    }
    let size = bound.saturating_add(1);
    let mut buf = Zeroizing::new(Vec::new());
    buf.try_reserve_exact(size)
        .map_err(|_| io(std::io::ErrorKind::OutOfMemory.into()))?;
    buf.resize(size, 0);
    let mut filled = 0;
    while filled < size {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io(e)),
        }
    }
    if filled > bound {
        return Err(too_large(None));
    }
    buf.truncate(filled);
    crate::secret::hold(std::mem::take(&mut *buf))
}

/// The [`TlsError::Io`] for a file [`read_capped`] or [`read_capped_secret`]
/// refused as over `bound` *(0.12.0)*: `what` names the file, and `len` is the
/// length it had, or `None` when it grew past the bound while it was read.
pub(crate) fn over_bound(path: &Path, what: &str, bound: usize, len: Option<u64>) -> TlsError {
    let detail = match len {
        Some(len) => {
            format!("{what} is {len} bytes, over the bound of {bound} bytes; it was not read")
        }
        None => format!(
            "{what} grew past the bound of {bound} bytes while it was read; what was read was not used"
        ),
    };
    TlsError::Io {
        path: Some(path.to_path_buf()),
        detail,
    }
}

/// `n` as `u64`, which holds every `usize` on the targets nettls builds for.
fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Creates `tmp` (it must not exist), writes `bytes`, sets `mode` and syncs.
fn write_new(tmp: &Path, bytes: &[u8], mode: u32) -> Result<(), TlsError> {
    let mut open = fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut f = open.open(tmp).map_err(|e| TlsError::io(tmp, e))?;
    f.write_all(bytes).map_err(|e| TlsError::io(tmp, e))?;
    #[cfg(unix)]
    {
        // Explicit: the mode given to `open` is filtered by the umask.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| TlsError::io(tmp, e))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    f.sync_all().map_err(|e| TlsError::io(tmp, e))
}

/// Syncs the directory `path` lives in, so a `rename` into it survives a
/// crash. `placed` says what is already in place, for the error a failed sync
/// gives *(0.12.0)*.
pub(crate) fn sync_dir(path: &Path, placed: &str) -> Result<(), TlsError> {
    sync_parent(path, |e| {
        format!(
            "{e}; {placed}, but the directory could not be synced, so the change may not \
             survive a crash"
        )
    })
}

/// Syncs the directory `path` lives in. `detail` words the error a failed sync
/// gives. On non-unix nothing is done.
fn sync_parent(path: &Path, detail: impl FnOnce(std::io::Error) -> String) -> Result<(), TlsError> {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| TlsError::Io {
                path: Some(dir.to_path_buf()),
                detail: detail(e),
            })?;
    }
    #[cfg(not(unix))]
    let _ = (path, detail);
    Ok(())
}

/// Creates `dir` and any missing parent with mode 0700. An existing directory
/// is left as it is.
pub(crate) fn create_private_dir(dir: &Path) -> Result<(), TlsError> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir).map_err(|e| TlsError::io(dir, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // (The base64 vectors live in krypto::base64 now — the body is its output;
    // the tests in `tests/files_and_auto.rs` read written PEM blocks back
    // end-to-end.)

    /// DER one byte over krypto's limit is `TlsError::Encode`, and the message
    /// carries krypto's own reason (0.12.0).
    #[test]
    fn der_over_the_limit_is_an_encode_error() {
        let der = vec![0u8; krypto::MAX_DATA_BYTES + 1];
        let krypto_reason = krypto::base64::encode(&der).unwrap_err().to_string();
        let err = encode("CERTIFICATE", &der).unwrap_err();
        let TlsError::Encode(msg) = &err else {
            panic!("expected TlsError::Encode, got {err:?}");
        };
        assert_eq!(*msg, format!("the DER as base64: {krypto_reason}"));
    }

    /// A label is 1 to 64 capital letters, digits and single spaces (0.12.0).
    #[test]
    fn a_label_outside_the_rule_is_params() {
        let at_bound = "A".repeat(MAX_LABEL_LEN);
        assert!(encode(&at_bound, b"x").is_ok());
        assert!(encode("X509 CRL", b"x").is_ok());

        let err = encode(&format!("{at_bound}A"), b"x").unwrap_err();
        assert!(matches!(err, TlsError::Params(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains("is 65 bytes, over the bound of 64 bytes"),
            "{err}"
        );
        for label in ["", "certificate", " CERTIFICATE", "PRIVATE  KEY", "KEY-1"] {
            let err = encode(label, b"x").unwrap_err();
            assert!(matches!(err, TlsError::Params(_)), "{label:?}: {err:?}");
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nettls-pem-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn a_leftover_temp_file_is_replaced_not_reused() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("leftover");
        let path = d.join("key.pem");
        // What an interrupted write leaves behind: content, and the umask's mode.
        fs::write(path.with_extension("tmp"), b"half a key").unwrap();
        fs::set_permissions(
            path.with_extension("tmp"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        write_atomic(&path, b"the key", 0o600).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"the key");
        assert_eq!(mode_of(&path), 0o600);
        assert!(!path.with_extension("tmp").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_where_the_temp_file_goes_is_not_followed() {
        let d = scratch("symlink");
        let path = d.join("key.pem");
        let elsewhere = d.join("elsewhere");
        fs::write(&elsewhere, b"not ours").unwrap();
        std::os::unix::fs::symlink(&elsewhere, path.with_extension("tmp")).unwrap();

        write_atomic(&path, b"the key", 0o600).unwrap();

        assert_eq!(fs::read(&elsewhere).unwrap(), b"not ours");
        assert_eq!(fs::read(&path).unwrap(), b"the key");
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// A pair whose staging fails leaves no temp file it made, and the stored
    /// pair as it was (0.12.0). A directory where the temp key goes stops it.
    #[test]
    fn a_pair_that_cannot_be_staged_leaves_no_temp_file_and_the_pair_as_it_was() {
        let d = scratch("pair-staging");
        let cert = d.join("cert.pem");
        let key = d.join("key.pem");
        fs::write(&cert, b"the old cert").unwrap();
        fs::write(&key, b"the old key").unwrap();
        fs::create_dir(temp_path(&key)).unwrap();

        write_pair(&cert, b"the new cert", 0o644, &key, b"the new key", 0o600).unwrap_err();

        assert!(!temp_path(&cert).exists());
        assert!(temp_path(&key).is_dir());
        assert_eq!(fs::read(&cert).unwrap(), b"the old cert");
        assert_eq!(fs::read(&key).unwrap(), b"the old key");
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn key_directories_are_created_0700_and_existing_ones_are_left_alone() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("dirs");
        let nested = d.join("a").join("b");
        create_private_dir(&nested).unwrap();
        assert_eq!(mode_of(&d.join("a")), 0o700);
        assert_eq!(mode_of(&nested), 0o700);

        let existing = d.join("existing");
        fs::create_dir(&existing).unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o750)).unwrap();
        create_private_dir(&existing).unwrap();
        assert_eq!(mode_of(&existing), 0o750);
        let _ = fs::remove_dir_all(&d);
    }
}
