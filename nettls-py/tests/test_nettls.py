# SPDX-License-Identifier: MIT OR Apache-2.0
"""nettls from Python, through nettls_py: the Rust code, run from Python (0.11.0).

The behaviour is the crate's and is tested there. What these tests show is that
Python gets it: the vectors come out byte for byte, the messages sign and verify,
the state machines answer the same, and every failure is the exception for its
`TlsError` variant.

The vectors in `testvectors/canonical.json` are normative. The Ed25519
signatures in them are made with krypto, as `tests/testvectors.rs` does.
"""

from __future__ import annotations

import json
import re

import nettls_py as nettls
import pytest
from support import ROOT, TESTVECTORS, ed25519_public, ed25519_sign, material

from nettls_py import canonical as c

VECTORS = json.loads((TESTVECTORS / "canonical.json").read_text())

# The same seed the Rust side uses for the vectors.
SEED = bytes(range(1, 33))

FP_A = "aa00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
FP_B = "bb00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
FP_C = "cc00112233445566778899aabbccddeeff00112233445566778899aabbccddee"


def build_vectors() -> dict[str, bytes]:
    """The same set as `tests/testvectors.rs`, built from Python."""
    return {
        "approve-01-plain": c.approve_v1("gateway", FP_A, "operator", 1_700_000_000),
        "approve-02-non-ascii": c.approve_v1("gateway", FP_A, "bjørn-øyvind", 1_700_000_000),
        "approve-03-time-zero": c.approve_v1("service", FP_B, "a", 0),
        "approve-04-time-negative": c.approve_v1("service", FP_B, "a", -1),
        "approve-05-max-lengths": c.approve_v1("p" * 32, FP_C, "u" * 64, 1),
        "rotate-01-double-signed": c.rotate_v2("gateway", FP_A, FP_B, FP_C, 1_700_000_000),
        "rotate-02-bootstrap": c.rotate_v2("gateway", None, FP_B, FP_C, 1_700_000_000),
        "ack-01-plain": c.rotate_ack_v2("service", "gateway", FP_C, 1_700_000_000),
        "pairsecret-01-plain": c.pairsecret_v1("service", "gateway", FP_A, FP_B, 1_700_000_000),
        "algsupport-01-python-bridge": c.algsupport_v1("service", "aes256gcm", 1_700_000_000),
    }


# --------------------------------------------------------------------------- #
# The vectors
# --------------------------------------------------------------------------- #


def test_the_vector_seed_has_the_vector_key():
    # Change the seed, and every signature vector is invalid.
    assert ed25519_public(SEED).hex() == (
        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
    )


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_vectors_match_byte_for_byte(name):
    expected = VECTORS[name]
    actual = build_vectors()[name]
    assert actual.hex() == expected["canonical_hex"], (
        f"vector «{name}» ({expected['what']}) does not match"
    )


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_vector_signatures_are_identical(name):
    # Ed25519 is deterministic: byte equality, not merely "it verifies".
    expected = VECTORS[name]
    sig = ed25519_sign(SEED, bytes.fromhex(expected["canonical_hex"]))
    assert sig.hex() == expected["ed25519_sig_hex"]


def test_no_vector_is_missing():
    assert set(VECTORS) == set(build_vectors())


def test_approval_and_receipt_sign_as_the_vectors():
    # nettls's own signing, not krypto's directly: the same bytes come out.
    g = nettls.approval.Approval.new("gateway", FP_A, "operator", 1_700_000_000, "portal", SEED)
    assert g.to_json().sig == VECTORS["approve-01-plain"]["ed25519_sig_hex"]
    r = nettls.announcement.Receipt.new("service", "gateway", FP_C, 1_700_000_000, SEED)
    assert r.to_json().sig == VECTORS["ack-01-plain"]["ed25519_sig_hex"]


# --------------------------------------------------------------------------- #
# The form, and the fields
# --------------------------------------------------------------------------- #


def test_no_trailing_newline_anywhere():
    for b in build_vectors().values():
        assert not b.endswith(b"\n"), b
        assert b"\r\n" not in b


def test_bootstrap_serializes_prev_as_dash():
    with_prev = c.rotate_v2("gateway", FP_A, FP_B, FP_C, 1)
    without = c.rotate_v2("gateway", None, FP_B, FP_C, 1)
    assert b"\n-\n" in without
    # The same number of lines: a missing field would shift the next one up.
    assert with_prev.count(b"\n") == without.count(b"\n")


def test_newline_in_a_field_is_rejected():
    with pytest.raises(nettls.TlsError):
        c.approve_v1("gateway", FP_A, "rog\ner", 1)
    with pytest.raises(nettls.TlsError):
        c.approve_v1("net\rgw", FP_A, "operator", 1)


def test_wrong_fingerprint_is_rejected():
    for bad in ["short", f"sha256:{FP_A}", FP_A.upper(), "z" * 64]:
        with pytest.raises(nettls.TlsError):
            c.approve_v1("gateway", bad, "operator", 1)


def test_require_checks_take_the_field_name_from_python():
    with pytest.raises(nettls.ParamsError, match="my_field"):
        c.require_fingerprint("abc", "my_field")
    with pytest.raises(nettls.ParamsError, match="their_name"):
        c.require_name("", "their_name", 10)


def test_hex_rejects_uppercase_and_garbage():
    assert nettls.signature.from_hex("000fa0ff") == bytes([0, 0x0F, 0xA0, 0xFF])
    for bad in ["000FA0FF", "abc", "", "zz"]:
        with pytest.raises(nettls.ProofError):
            nettls.signature.from_hex(bad)


# --------------------------------------------------------------------------- #
# Announcement and receipt (§6.5, §6.6)
# --------------------------------------------------------------------------- #

Announcement = nettls.announcement.Announcement
AnnouncementJson = nettls.announcement.AnnouncementJson
Receipt = nettls.announcement.Receipt


def test_bootstrap_accepted_without_previous():
    _, k0, fp0, der0 = material("c0")
    c1, _, _, _ = material("c1")
    k = Announcement.new("gateway", None, (fp0, k0), c1, 100)
    assert k.is_bootstrap()
    k.verify(None, der0)


def test_single_signature_rejected_when_receiver_has_previous():
    # Asking through with fewer signatures by leaving `prev` out.
    _, _, _, der0 = material("c0")
    _, k1, fp1, der1 = material("c1")
    c2, _, _, _ = material("c2")
    k = Announcement.new("gateway", None, (fp1, k1), c2, 100)
    with pytest.raises(nettls.TlsError, match="single-signed"):
        k.verify(der0, der1)


def test_double_signed_accepted():
    _, k0, fp0, der0 = material("c0")
    _, k1, fp1, der1 = material("c1")
    c2, _, _, _ = material("c2")
    Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 100).verify(der0, der1)


def test_swapped_certificate_rejected_even_with_valid_signatures():
    # The signatures cover the fingerprint, not the certificate.
    _, k0, fp0, der0 = material("c0")
    _, k1, fp1, der1 = material("c1")
    c2, _, _, _ = material("c2")
    evil, _, _, _ = material("evil")
    j = Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 100).to_json()
    j.new_cert_pem = evil
    with pytest.raises(nettls.TlsError, match="swapped in transit"):
        Announcement.from_json(j).verify(der0, der1)


def test_json_roundtrip_preserves_everything():
    _, k0, fp0, _ = material("c0")
    _, k1, fp1, _ = material("c1")
    c2, _, _, _ = material("c2")
    k = Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 1_700_000_000)
    text = k.to_json().dumps()
    assert Announcement.from_json(AnnouncementJson.loads(text)) == k
    assert json.loads(text)["new_fingerprint"] == k.new_fingerprint()


def test_half_announcement_is_rejected():
    _, k0, fp0, _ = material("c0")
    _, k1, fp1, _ = material("c1")
    c2, _, _, _ = material("c2")
    j = Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 1).to_json()
    j.sig_prev = None
    with pytest.raises(nettls.ProofError):
        Announcement.from_json(j)


def test_invalid_json_is_a_value_error():
    with pytest.raises(ValueError, match="invalid JSON"):
        AnnouncementJson.loads('{"v": 1}')


def test_receipt_rejects_replay():
    pk = ed25519_public(SEED)
    r = Receipt.new("service", "gateway", FP_B, 100, SEED)
    r.verify(pk, FP_B)
    with pytest.raises(nettls.TlsError, match="a different rotation"):
        r.verify(pk, FP_A)


# --------------------------------------------------------------------------- #
# Generation 0, and one code path for both kinds (M-9)
# --------------------------------------------------------------------------- #

Approval = nettls.approval.Approval


def registry(key_id: str) -> bytes | None:
    return ed25519_public(SEED) if key_id == "portal" else None


def test_approval_verifies_and_rejects_tampering():
    g = Approval.new("gateway", FP_A, "operator", 100, "portal", SEED)
    g.verify(registry)
    j = g.to_json()
    j.approved_by = "someone-else"
    with pytest.raises(nettls.ProofInvalidError):
        Approval.from_json(j).verify(registry)


def test_unknown_key_id_says_anchor_cannot_be_verified():
    g = Approval.new("gateway", FP_A, "operator", 100, "op:operator", SEED)
    with pytest.raises(nettls.TlsError, match="is not an anchor"):
        g.verify(lambda key_id: None)


def test_an_exception_in_the_lookup_is_raised_not_swallowed():
    g = Approval.new("gateway", FP_A, "operator", 100, "portal", SEED)

    def broken(key_id):
        raise LookupError("the registry is down")

    with pytest.raises(LookupError, match="the registry is down"):
        g.verify(broken)


def test_recognition_verifies_both_kinds():
    ap = nettls.approval
    g = Approval.new("gateway", FP_A, "operator", 100, "portal", SEED)
    ctx = ap.Context(registry, None, None)
    op = ap.Recognition.Operator(g)
    op.verify(ctx)
    assert op.is_anchor() and op.fingerprint() == FP_A

    _, k0, fp0, der0 = material("c0")
    c1, _, fp1, _ = material("c1")
    k = Announcement.new("gateway", None, (fp0, k0), c1, 1)
    sched = ap.Recognition.Schedule(k)
    sched.verify(ap.Context(registry, None, der0))
    assert not sched.is_anchor() and sched.fingerprint() == fp1


# --------------------------------------------------------------------------- #
# The generations (§6.3) and restore (§6.8)
# --------------------------------------------------------------------------- #

G = nettls.generations


def test_the_two_roles_are_not_the_same():
    _, k0, fp0, der0 = material("c0")
    c1, k1, fp1, _ = material("c1")
    c2, _, fp2, _ = material("c2")
    g = G.Generations.from_approval(G.Generation.from_der(der0))
    g.receive(Announcement.new("gateway", None, (fp0, k0), c1, 1))
    assert g.observed(fp1)
    g.receive(Announcement.new("gateway", (fp0, k0), (fp1, k1), c2, 2))
    in_handshake = [x.fingerprint() for x in g.accepted_in_handshake()]
    assert fp1 in in_handshake and fp2 in in_handshake
    assert fp0 not in in_handshake, "previous must NOT be accepted in a handshake"
    assert g.for_signing()[0].fingerprint() == fp0


def test_receive_is_idempotent():
    _, k0, fp0, der0 = material("c0")
    c1, _, _, _ = material("c1")
    g = G.Generations.from_approval(G.Generation.from_der(der0))
    k = Announcement.new("gateway", None, (fp0, k0), c1, 1)
    assert g.receive(k) == G.Received.Stored
    assert g.receive(k) == G.Received.Known


def test_restored_state_accepts_double_signed_announcement():
    p0, k0, fp0, _ = material("c0")
    p1, k1, fp1, _ = material("c1")
    p2, _, _, _ = material("c2")
    g0, g1 = G.Generation.from_pem(p0), G.Generation.from_pem(p1)
    k = Announcement.new("gateway", (fp0, k0), (fp1, k1), p2, 1_700_000_000)
    # A8: an anchor-only receiver accepts what it can verify.
    assert G.Generations.from_approval(g1).receive(k) == G.Received.Stored
    assert G.Generations.restore(g0, g1, None).receive(k) == G.Received.Stored


def test_restored_next_accepted_in_handshake_and_promoted():
    g0, g1, g2 = (G.Generation.from_pem(material(n)[0]) for n in ("c0", "c1", "c2"))
    g = G.Generations.restore(g0, g1, g2)
    fps = [x.fingerprint() for x in g.accepted_in_handshake()]
    assert g1.fingerprint() in fps and g2.fingerprint() in fps
    assert g.observed(g2.fingerprint())
    assert g.current() == g2 and g.previous() == g1


def test_restore_rejects_impossible_states():
    g0, g1 = (G.Generation.from_pem(material(n)[0]) for n in ("c0", "c1"))
    for previous, current, nxt in [(g1, g1, None), (None, g1, g1), (g0, g1, g0)]:
        with pytest.raises(nettls.TlsError):
            G.Generations.restore(previous, current, nxt)


def test_trust_shares_its_state():
    _, k0, fp0, der0 = material("c0")
    c1, _, fp1, _ = material("c1")
    t = G.Trust.from_approval(G.Generation.from_der(der0))
    assert t.receive(Announcement.new("gateway", None, (fp0, k0), c1, 1)) == G.Received.Stored
    assert t.state().next().fingerprint() == fp1


# --------------------------------------------------------------------------- #
# Modes, lifetimes and warnings (M-11, M-12, M-21)
# --------------------------------------------------------------------------- #

A = nettls.announcer


def test_mode_is_never_negotiated():
    assert A.check_mode(A.Mode.Rolling, A.Mode.Rolling) == A.ModeCheck.Agree(A.Mode.Rolling)
    m = A.check_mode(A.Mode.Rolling, A.Mode.Pinning)
    assert isinstance(m, A.ModeCheck.Disagree) and not m.can_roll()
    text = m.message("peer")
    assert "rolling" in text and "pinning" in text
    assert str(A.Mode.Pinning) == "pinning"


def test_mode2_lifetime_is_thirty_days_and_backdated_one_hour():
    assert A.MODE2_LIFETIME_DAYS == 30
    params = A.mode2_params("x", ["x"])
    assert params.valid_days == 30
    m = nettls.TlsMaterial.load(nettls.CertSource.self_signed(params))
    assert m.not_after() - m.not_before() == 30 * A.DAY_S + 3600


def test_mode1_warns_at_thirty_days_left():
    expires = 1_000 * A.DAY_S
    assert not A.mode1_should_warn(expires - 31 * A.DAY_S, expires)
    assert A.mode1_should_warn(expires - 30 * A.DAY_S, expires)
    assert A.mode1_should_warn(expires + A.DAY_S, expires)


def test_mode1_lifetime_has_floor_and_ceiling():
    assert A.mode1_params("x", ["x"], None).valid_days == A.MODE1_DEFAULT_DAYS == 90
    assert A.mode1_params("x", ["x"], 47).valid_days == 47
    assert A.mode1_params("x", ["x"], 365).valid_days == 365
    with pytest.raises(nettls.ParamsError, match="below the floor"):
        A.mode1_params("x", ["x"], 46)
    with pytest.raises(nettls.ParamsError, match="above the ceiling"):
        A.mode1_params("x", ["x"], 366)


def test_empty_san_list_is_rejected():
    with pytest.raises(nettls.ParamsError, match="the SAN list is empty"):
        nettls.TlsMaterial.load(nettls.CertSource.self_signed(nettls.SelfSignedParams.new("x", [])))


def test_a_broken_pin_is_an_error():
    with pytest.raises(nettls.FingerprintError):
        nettls.pinned_client_config("")


# --------------------------------------------------------------------------- #
# The schedule: alarm, retries and the countdown (M-7c, M-7d, M-7e)
# --------------------------------------------------------------------------- #


def test_alarm_fires_after_twelve_hours_not_before():
    r = A.Schedule(["service"], 0)
    r.announced(1000)
    assert not r.alarm(1000)
    assert not r.alarm(1000 + A.ALARM_AFTER_S - 1)
    assert r.alarm(1000 + A.ALARM_AFTER_S)


def test_receipt_stops_the_alarm():
    r = A.Schedule(["service"], 0)
    r.announced(1000)
    r.acked("service")
    assert not r.alarm(1000 + A.ALARM_AFTER_S)
    assert isinstance(r.state(), A.ChainState.Announced)
    assert r.state().waiting_for == []


def test_retries_continue_after_the_alarm():
    r = A.Schedule(["service"], 0)
    r.announced(0)
    for elapsed in (0, 15 * 60, 3600, 24 * 3600):
        assert r.next_retry(elapsed) is not None


def test_retry_cadence_is_dense_at_the_start():
    assert A.interval_after(0) == 60
    assert A.interval_after(15 * 60 - 1) == 60
    assert A.interval_after(15 * 60) == 5 * 60
    assert A.interval_after(3600 - 1) == 5 * 60
    assert A.interval_after(3600) == 3600


def test_countdown_changes_as_time_passes():
    r = A.Schedule(["service"], 0)
    r.announced(0)
    expires = 30 * A.DAY_S
    a = r.status(0, expires).countdown()
    b = r.status(10 * A.DAY_S, expires).countdown()
    assert a and b and a != b


def test_clock_drift():
    d = A.ClockDrift()
    assert d.observe(1000, 1000) == A.Drift.Normal
    assert d.observe(1000, 1000 + A.DRIFT_WARNING_S + 1) == A.Drift.Warning
    assert d.max() >= A.DRIFT_WARNING_S


# --------------------------------------------------------------------------- #
# Lock at rest (§8.4) and the sealed envelope (§8.5)
# --------------------------------------------------------------------------- #

L = nettls.lockbox
E = nettls.envelope


def test_lock_roundtrip_with_every_algorithm():
    for alg in (nettls.Alg.Aegis256, nettls.Alg.XChaCha20Poly1305, nettls.Alg.Aes256Gcm):
        f = L.lock_with("secret-password", b"peer registry + keys", alg)
        assert L.unlock("secret-password", f) == b"peer registry + keys"


def test_wrong_password_gives_authentication_failure():
    f = L.lock("secret-password", b"x")
    with pytest.raises(nettls.TlsError, match="wrong password"):
        L.unlock("another-password", f)


def test_no_phc_hash_in_the_file():
    f = L.lock("secret-password", b"x")
    assert b"$argon2" not in f
    assert f[:8] == b"NETTLS\x01\x00"
    assert f[8 + 32 : 8 + 32 + 4] == b"FAFN"


def test_altered_file_rejected():
    f = bytearray(L.lock("secret-password", b"something important"))
    f[-1] ^= 1
    with pytest.raises(nettls.TlsError):
        L.unlock("secret-password", bytes(f))


def test_wrong_format_says_it_is_the_format():
    with pytest.raises(nettls.TlsError, match="unknown file format"):
        L.unlock("x", b"this is quite definitely not a locked file at all")


def test_envelope_roundtrip_and_public_part():
    key, public = E.RecipientKey.generate()
    assert key.public() == public
    k = E.seal(public, b"something only the recipient may see")
    assert E.open(key, k) == b"something only the recipient may see"
    k = E.seal_with(public, b"x", nettls.Alg.Aes256Gcm)
    assert E.open(key, k) == b"x"


def test_sender_cannot_open_own_envelope():
    _, public = E.RecipientKey.generate()
    k = E.seal(public, b"device-password")
    with pytest.raises(nettls.TlsError):
        E.open(E.RecipientKey.from_bytes(public), k)


def test_wrong_recipient_does_not_get_in():
    _, public = E.RecipientKey.generate()
    other, _ = E.RecipientKey.generate()
    with pytest.raises(nettls.TlsError, match="not sealed to this"):
        E.open(other, E.seal(public, b"x"))


def test_envelope_wrong_format_and_length():
    key, _ = E.RecipientKey.generate()
    with pytest.raises(nettls.TlsError, match="not a nettls envelope"):
        E.open(key, b"NETTLS\x01\x00 this is a locked file, not an envelope")
    with pytest.raises(nettls.TlsError, match="too short"):
        E.open(key, b"short")
    with pytest.raises(nettls.TlsError, match="32 bytes"):
        E.seal(b"too short", b"x")


# --------------------------------------------------------------------------- #
# The signed support statement (capability)
# --------------------------------------------------------------------------- #


def test_support_statement_roundtrip_and_fallback_rule():
    cap = nettls.capability
    _, key, _, der = material("service")
    st = cap.SupportStatement.signed("service", [nettls.Alg.Aes256Gcm], 1_700_000_000, key)
    assert st.verify(der) == [nettls.Alg.Aes256Gcm]
    assert cap.SupportStatement.loads(st.dumps()).verify(der) == [nettls.Alg.Aes256Gcm]

    st.supported = ["aegis256", "aes256gcm"]
    with pytest.raises(nettls.TlsError):
        st.verify(der)

    a, x, g = nettls.Alg.Aegis256, nettls.Alg.XChaCha20Poly1305, nettls.Alg.Aes256Gcm
    assert cap.choose(a, None) == a
    assert cap.choose(a, [g]) == g
    assert cap.choose(a, [a, g]) == a
    assert cap.alg_from_token(cap.alg_token(x)) == x
    with pytest.raises(nettls.NegotiationError, match="no acceptable algorithm"):
        cap.choose(a, [])


# --------------------------------------------------------------------------- #
# The announcer keeps its own state on disk (§6.11b)
# --------------------------------------------------------------------------- #


def anchor_material():
    """Generation 0: the identity the operator approved."""
    return nettls.TlsMaterial.load(nettls.CertSource.self_signed(A.mode2_params("gw", ["gw"])))


def announcer_in(path, anchor):
    """An announcer over `path`, as a service builds one at every start."""
    resolver = nettls.RotatingResolver(anchor)
    own = A.OwnMaterial(None, (anchor.fingerprint_sha256(), anchor.anchor_pkcs8()))
    return A.Announcer.new(
        "gw", path, A.mode2_params("gw", ["gw"]), resolver, own, A.Schedule(["peer"], 0), "pw"
    )


def test_the_announcer_survives_a_restart(tmp_path):
    anchor = anchor_material()
    fp = anchor.fingerprint_sha256()
    a = announcer_in(tmp_path, anchor)
    k = a.prepare(100)
    assert a.own_trio().next_fingerprint == k.new_fingerprint()

    # A restart: the promise and who is to ack are on disk.
    b = announcer_in(tmp_path, anchor)
    assert b.pending() == k
    assert b.roll_if_ready(200) is None, "no receipt yet"
    b.acked("peer")
    assert b.roll_if_ready(200) == fp
    assert b.own_trio().current_fingerprint == k.new_fingerprint()

    # Another restart: the switch is kept, and so is the 24-hour cap.
    c = announcer_in(tmp_path, anchor)
    assert c.own_trio().current_fingerprint == k.new_fingerprint()
    c.prepare(300)
    c.acked("peer")
    assert c.roll_if_ready(300) is None
    assert c.roll_if_ready(200 + A.MIN_BETWEEN_ROLLS_S) is not None


def test_own_material_is_taken_by_the_announcer(tmp_path):
    _, key, fp, _ = material("gw")
    own = A.OwnMaterial(None, (fp, key))
    assert own.current == (fp, key)
    m = nettls.TlsMaterial.load(nettls.CertSource.self_signed(A.mode2_params("gw", ["gw"])))
    A.Announcer.new(
        "gw", tmp_path, A.mode2_params("gw", ["gw"]), nettls.RotatingResolver(m), own,
        A.Schedule([], 0), "pw",
    )
    with pytest.raises(ValueError, match="given to an Announcer"):
        own.current


def test_a_raising_gate_switches_nothing(tmp_path):
    anchor = anchor_material()
    fp = anchor.fingerprint_sha256()
    a = announcer_in(tmp_path, anchor)
    a.prepare(100)
    a.acked("peer")

    def gate():
        raise RuntimeError("cannot tell")

    with pytest.raises(RuntimeError, match="cannot tell"):
        a.roll_if_ready_gated(200, gate)
    assert a.own_trio().current_fingerprint == fp
    assert a.roll_if_ready_gated(200, lambda: True) == fp


# --------------------------------------------------------------------------- #
# The status report, and the version
# --------------------------------------------------------------------------- #


def test_status_report_is_the_rust_json():
    st = nettls.status
    m = nettls.TlsMaterial.load(nettls.CertSource.self_signed(A.mode2_params("gw", ["gw"])))
    g = G.Generations.from_approval(G.Generation.from_der(material("peer")[3]))
    report = st.Report.collect(m.not_before(), m, None, [st.PeerReport.from_generations("peer", g)])
    data = json.loads(report.dumps())
    assert data["version"] == nettls.VERSION
    assert data["identity"]["fingerprint_sha256"] == m.fingerprint_sha256()
    assert data["peers"][0]["state"] == "ok"
    assert report.summary().level == report.level


def test_the_version_is_the_crates():
    manifest = (ROOT / "Cargo.toml").read_text()
    declared = re.search(r'^version\s*=\s*"([^"]+)"', manifest, re.M).group(1)
    assert nettls.VERSION == nettls.__version__ == declared
