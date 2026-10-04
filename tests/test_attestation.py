"""Trust level 3 (SPEC §7.1, §10 step 5): the AWS Nitro attestation check, via the conformance vectors 042-048,
the real fixture, cumulative-level logic and the strict CBOR decoder."""
from __future__ import annotations

import copy
import json
import sys
import types
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

import qed_proof
from qed_proof import AttestationError, _nitro as N, _primitives as ref, verify_receipt

HERE = Path(__file__).parent
VECTORS = HERE / "vectors"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text())


def _root_der(name: str) -> bytes:
    return x509.load_pem_x509_certificate((VECTORS / name).read_bytes()).public_bytes(Encoding.DER)


def _vec(name: str):
    return json.loads((VECTORS / name).read_text())


@pytest.mark.parametrize("entry", MANIFEST["attestation_vectors"], ids=lambda e: e["file"])
def test_attestation_vector_matches_expected_report(entry):
    receipt = _vec(entry["file"])
    keys = _vec(entry["keyset"])
    report = verify_receipt(receipt, keys, nitro_root=_root_der(entry["nitro_root"])).to_dict()
    assert report == entry["expected"], f"{entry['file']}: {entry['description']}"


def test_manifest_covers_all_attestation_vectors():
    assert [e["file"][:3] for e in MANIFEST["attestation_vectors"]] == ["042", "043", "044", "045", "046", "047", "048"]


def test_pinned_aws_root_is_not_the_test_root():
    # Without the test-only override the test enclave's chain must not verify against the real AWS root.
    entry = MANIFEST["attestation_vectors"][0]
    report = verify_receipt(_vec(entry["file"]), _vec(entry["keyset"]))
    assert report.checks["attestation"] == "attestation_chain"
    assert report.achieved_trust_level == 1


def test_root_pin_hash():
    import hashlib
    assert hashlib.sha256(N.NITRO_ROOT_DER).hexdigest() == N.NITRO_ROOT_SHA256


def test_real_nitro_fixture_verifies_against_pinned_root():
    fx = json.loads((HERE / "fixtures" / "nitro-live-build2.json").read_text())
    att = N.verify_nitro_attestation(fx["attestation"])
    assert att.pcrs[0].hex() == fx["expected_pcr0"]
    assert att.digest == "SHA384" and len(att.user_data) == 32


def test_real_nitro_fixture_tampered_signature_fails():
    fx = json.loads((HERE / "fixtures" / "nitro-live-build2.json").read_text())
    raw = bytearray(ref.b64u_decode(fx["attestation"]))
    raw[-1] ^= 0x01  # last byte of the COSE signature
    with pytest.raises(AttestationError) as e:
        N.verify_nitro_attestation(ref.b64u(bytes(raw)))
    assert e.value.reason == "attestation_invalid"


def test_tampered_document_bytes_never_pass():
    receipt = _vec("042-l3-valid.json")
    keys = _vec("keys-l3.json")
    root = _root_der("nitro-test-root.pem")
    raw = ref.b64u_decode(receipt["attestation_document"])
    for i in (len(raw) // 2, len(raw) - 5):
        bad = bytearray(raw)
        bad[i] ^= 0x01
        r = copy.deepcopy(receipt)
        r["attestation_document"] = ref.b64u(bytes(bad))
        report = verify_receipt(r, keys, nitro_root=root)
        assert report.checks["attestation"] is not True
        assert report.achieved_trust_level == 1


def test_missing_document_is_attestation_invalid():
    receipt = _vec("042-l3-valid.json")
    del receipt["attestation_document"]
    report = verify_receipt(receipt, _vec("keys-l3.json"), nitro_root=_root_der("nitro-test-root.pem"))
    assert report.checks["attestation"] == "attestation_invalid"
    assert report.valid is True and report.achieved_trust_level == 1


def test_below_level_three_has_no_attestation_check():
    report = verify_receipt(_vec("001-valid-verified.json"), _vec(MANIFEST["keyset"]))
    assert "attestation" not in report.checks


# --- cumulative: level 3 needs level 2 -------------------------------------------------------------------------
def _anchored_l3():
    receipt = _vec("042-l3-valid.json")
    receipt["proof"] = {
        "log_id": "AAAA", "leaf_index": 0, "tree_size": 1, "root_hash": ref.b64u(ref.leaf_hash(receipt)), "inclusion": [],
        "anchor": {"chain": "eip155:84532", "scheme": "eas", "uid": "0x" + "22" * 32, "tx_hash": "0x" + "11" * 32,
                   "tree_size": 1}}
    return receipt


@pytest.fixture
def fake_anchor(monkeypatch):
    fake = types.ModuleType("qed_proof._anchor")
    fake.ok = True
    fake.check_anchor = lambda *a, **k: {"ok": fake.ok, "reason": None if fake.ok else "anchor_missing", "proven_by": 1}
    monkeypatch.setitem(sys.modules, "qed_proof._anchor", fake)
    monkeypatch.setattr(qed_proof, "_anchor", fake, raising=False)
    return fake


def test_level_three_achieved_with_anchor_and_attestation(fake_anchor):
    report = verify_receipt(_anchored_l3(), _vec("keys-l3.json"), rpc_url="http://rpc",
                            nitro_root=_root_der("nitro-test-root.pem"))
    assert report.checks["inclusion"] is True and report.checks["anchor"] is True and report.checks["attestation"] is True
    assert report.achieved_trust_level == 3


def test_attestation_without_anchor_stays_level_one(fake_anchor):
    report = verify_receipt(_anchored_l3(), _vec("keys-l3.json"), nitro_root=_root_der("nitro-test-root.pem"))
    assert report.checks["anchor"] == "not_checked_offline" and report.checks["attestation"] is True
    assert report.achieved_trust_level == 1


def test_failed_attestation_caps_anchored_receipt_at_level_two(fake_anchor):
    report = verify_receipt(_anchored_l3(), _vec("keys-l3.json"), rpc_url="http://rpc")  # wrong (pinned AWS) root
    assert report.checks["attestation"] == "attestation_chain"
    assert report.valid is True and report.achieved_trust_level == 2


def test_failed_anchor_with_good_attestation_is_not_level_three(fake_anchor):
    fake_anchor.ok = False
    report = verify_receipt(_anchored_l3(), _vec("keys-l3.json"), rpc_url="http://rpc",
                            nitro_root=_root_der("nitro-test-root.pem"))
    assert report.checks["attestation"] is True and report.achieved_trust_level == 1


def test_invalid_receipt_never_reaches_level_three(fake_anchor):
    r = _anchored_l3()
    r["body"]["verdict"]["value"] = "refuted"  # breaks the signature
    report = verify_receipt(r, _vec("keys-l3.json"), rpc_url="http://rpc", nitro_root=_root_der("nitro-test-root.pem"))
    assert report.valid is False and report.achieved_trust_level == 0


# --- strict CBOR ------------------------------------------------------------------------------------------------
def test_indefinite_length_items_decode_and_a_stray_break_does_not():
    assert N.cbor_decode(bytes.fromhex("bf616101616202ff")) == {"a": 1, "b": 2}
    assert N.cbor_decode(bytes.fromhex("9f0102ff")) == [1, 2]
    assert N.cbor_decode(bytes.fromhex("5f4201024103ff")) == b"\x01\x02\x03"
    for bad in ("bf6161", "ff", "bf616101616101ff", "5f6161ff"):  # no break, lone break, duplicate key, mixed chunk
        with pytest.raises(ValueError):
            N.cbor_decode(bytes.fromhex(bad))


@pytest.mark.parametrize("bad", [
    "f90000",  # float16
    "fb0000000000000000",  # float64
    "c100",  # tag
    "0000",  # trailing bytes
    "5801",  # truncated byte string
    "7ffe",  # unterminated
    "7f4100ff",  # text chunk is bytes
    "a1f6f6",  # null map key
    "a1f500",  # bool map key
    "1c",  # reserved additional info
    "",  # empty
    "83010203" "04",  # trailing after array
    "9a7fffffff00",  # huge declared array
])
def test_cbor_rejects(bad):
    with pytest.raises(ValueError):
        N.cbor_decode(bytes.fromhex(bad))


def test_cbor_depth_limit():
    with pytest.raises(ValueError):
        N.cbor_decode(b"\x81" * 40 + b"\x00")
    assert N.cbor_decode(b"\x81" * 10 + b"\x00") is not None


def test_cbor_scalars():
    assert N.cbor_decode(bytes.fromhex("20")) == -1
    assert N.cbor_decode(bytes.fromhex("1903e8")) == 1000
    assert N.cbor_decode(bytes.fromhex("f6")) is None
    assert N.cbor_decode(bytes.fromhex("f5")) is True
    assert N.cbor_decode(bytes.fromhex("6161")) == "a"


def test_non_base64_and_garbage_documents_are_attestation_invalid():
    for doc in ("!!!not base64!!!", ref.b64u(b"\xd2\x84\x40\xa0\x40\x40"), ref.b64u(b"junk")):
        with pytest.raises(AttestationError) as e:
            N.verify_nitro_attestation(doc)
        assert e.value.reason == "attestation_invalid"
