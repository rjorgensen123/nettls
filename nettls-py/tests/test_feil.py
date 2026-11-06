# SPDX-License-Identifier: MIT OR Apache-2.0
"""The error matrix from Python (SPEC-nettls §6.14b), through nettls_py.

It reads the same corpus as `tests/errors.rs`, `testvectors/errors.json`, and
holds every entry to the same levels:

- ``parse``: reading must reject. As in Rust, that is serde (here `loads`, a
  `ValueError`) or `from_json` (a `TlsError`).
- ``verify``: reading may accept, but verification must reject, with a
  `TlsError`.

Any other exception type means the value was never validated and crashed
somewhere further in. Two directions, as in Rust: INCOMING (the corpus, built
by hand the way an attacker would) and OUTGOING (the constructors refuse to
build anything invalid).
"""

from __future__ import annotations

import json

import nettls_py as nettls
import pytest
from support import TESTVECTORS

from nettls_py import announcement, approval
from nettls_py.signature import from_hex

CORPUS = json.loads((TESTVECTORS / "errors.json").read_text())
BASELINE = CORPUS["_valid"]

READERS = {
    "announcement": lambda j: announcement.Announcement.from_json(
        announcement.AnnouncementJson.loads(json.dumps(j))
    ),
    "receipt": lambda j: announcement.Receipt.from_json(
        announcement.ReceiptJson.loads(json.dumps(j))
    ),
    "approval": lambda j: approval.Approval.from_json(approval.ApprovalJson.loads(json.dumps(j))),
}


def _verify_kind(kind: str, obj) -> None:
    """Verification for the kind, with the baseline's keys."""
    pub = from_hex(BASELINE["ed25519_pub"])
    if kind == "announcement":
        obj.verify(
            announcement.der_from_pem(BASELINE["prev_cert_pem"]),
            announcement.der_from_pem(BASELINE["curr_cert_pem"]),
        )
    elif kind == "receipt":
        obj.verify(pub, obj.new_fingerprint())
    else:
        obj.verify(lambda key_id: pub if key_id == "portal" else None)


def _entries(kind: str):
    return [pytest.param(p, id=p["name"]) for p in CORPUS[kind]]


@pytest.mark.parametrize("kind", ["announcement", "receipt", "approval"])
def test_baseline_is_accepted_and_verifies(kind):
    """Positive control, first: otherwise the corpus could pass for the wrong
    reason, with everything rejected because the field names were wrong."""
    _verify_kind(kind, READERS[kind](BASELINE[kind]))


@pytest.mark.parametrize("post", _entries("announcement"))
def test_incoming_announcement_is_rejected(post):
    _require_rejected("announcement", post)


@pytest.mark.parametrize("post", _entries("receipt"))
def test_incoming_receipt_is_rejected(post):
    _require_rejected("receipt", post)


@pytest.mark.parametrize("post", _entries("approval"))
def test_incoming_approval_is_rejected(post):
    _require_rejected("approval", post)


def _require_rejected(kind: str, post: dict) -> None:
    """Rejected at the right level, with the right exception type, never passed."""
    try:
        obj = READERS[kind](post["json"])
    except (ValueError, nettls.TlsError):
        if post["level"] == "verify":
            raise AssertionError(
                f"{post['name']}: rejected while reading, but marked «verify»: "
                f"something other than «{post['field']}» failed first"
            ) from None
        return
    except Exception as e:  # noqa: BLE001
        raise AssertionError(
            f"{post['name']}: {type(e).__name__} instead of TlsError: the field "
            f"«{post['field']}» was never validated ({e})"
        ) from e

    if post["level"] == "parse":
        raise AssertionError(
            f"{post['name']}: ACCEPTED while reading; it should be rejected because "
            f"{post['why']} (field: {post['field']})"
        )
    try:
        _verify_kind(kind, obj)
    except nettls.TlsError:
        return
    except Exception as e:  # noqa: BLE001
        raise AssertionError(
            f"{post['name']}: verification failed with {type(e).__name__} instead of TlsError"
        ) from e
    raise AssertionError(
        f"{post['name']}: ACCEPTED by verification; it should be rejected because "
        f"{post['why']} (field: {post['field']})"
    )


# --------------------------------------------------------------------------- #
# OUTGOING: the constructors refuse to build anything invalid
# --------------------------------------------------------------------------- #

LF = "gateway\nfake"
NEL = "gateway\u0085"  # U+0085 NEL, category Cc: invisible, hence the escape
VALID_FP = "ab" * 32


@pytest.mark.parametrize(
    "value",
    [LF, NEL, "gateway\x00", "", "x" * 33, "Gateway", "gate_way"],
    ids=["newline", "c1_control", "null_byte", "empty", "too_long", "uppercase", "underscore"],
)
def test_outgoing_names_are_rejected(value):
    with pytest.raises(nettls.TlsError):
        nettls.canonical.approve_v1(value, VALID_FP, "operator", 1)


@pytest.mark.parametrize(
    "value",
    [VALID_FP.upper(), "abc", "ab" * 33, "sha256:" + VALID_FP, "g" * 64, ""],
    ids=["uppercase", "too_short", "too_long", "with_prefix", "not_hex", "empty"],
)
def test_outgoing_fingerprints_are_rejected(value):
    with pytest.raises(nettls.TlsError):
        nettls.canonical.approve_v1("gateway", value, "operator", 1)


@pytest.mark.parametrize(
    "value",
    ["a€", "ABCD", "abc", "", "zzzz"],
    ids=["multibyte_utf8", "uppercase", "odd", "empty", "not_hex"],
)
def test_outgoing_hex_is_rejected(value):
    with pytest.raises(nettls.TlsError):
        from_hex(value)


def test_outgoing_approval_rejects_invalid_key_id():
    with pytest.raises(nettls.TlsError):
        approval.Approval.new("gateway", VALID_FP, "operator", 1, LF, bytes(32))
