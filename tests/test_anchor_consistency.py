"""SPEC §8.4: the anchor check connects differing tree sizes with a consistency proof (needs the 'anchor' extra)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from qed_proof import verify_receipt

VECTORS = Path(__file__).parent / "vectors"


def _vec(name):
    return json.loads((VECTORS / name).read_text())


KEYSET = json.loads((VECTORS / json.loads((VECTORS / "manifest.json").read_text())["keyset"]).read_text())
CONS = _vec("040-consistency-valid.json")


# --- anchor consistency path (SPEC §8.4) -----------------------------------------------------------
eth_abi = pytest.importorskip("eth_abi", reason="requires the 'anchor' extra")
from eth_abi import encode  # noqa: E402

from qed_proof import _anchor as A  # noqa: E402
from qed_proof import _primitives as p  # noqa: E402
from qed_proof.log import consistency_source  # noqa: E402

ATTESTER = "0x23a848B41db0f152b7B9811e8314B6531dFAe523"
SCHEMA = b"\x5c" * 32
UID = b"\x77" * 32
LOG = p.b64u_decode(CONS["log_id"])
KEYS = {"anchor_addresses": [ATTESTER], "anchor_schemas": ["0x" + SCHEMA.hex()]}


def _chain(size, root_b64):
    data = encode(A._DATA, [LOG, size, p.b64u_decode(root_b64), 0, b"\x00" * 32, "poaw/0.1"])
    att = encode([A._ATT], [(UID, SCHEMA, 1790000000, 0, 0, b"\x00" * 32, "0x" + "00" * 20, ATTESTER, False, data)])
    return lambda url, method, *params: hex(84532) if method == "eth_chainId" else "0x" + att.hex()


def _proof(size, root, leaf=0):
    return {"log_id": CONS["log_id"], "leaf_index": leaf, "tree_size": size, "root_hash": root,
            "anchor": {"chain": "eip155:84532", "scheme": "eas", "uid": "0x" + UID.hex(), "tx_hash": "0x" + "11" * 32,
                       "tree_size": 7 if size == 3 else 3}}


def _run(monkeypatch, rpc, proof, consistency=None):
    monkeypatch.setattr(A, "_rpc", rpc)
    return A.check_anchor(proof, KEYS, "http://rpc", p.b64u_decode, consistency_source(consistency) if consistency else None)


def test_anchor_larger_than_receipt_with_valid_proof_passes(monkeypatch):  # receipt at 3, anchor at 7
    r = _run(monkeypatch, _chain(7, CONS["second_root"]), _proof(3, CONS["first_root"]), CONS)
    assert r == {"ok": True, "reason": "anchored", "proven_by": 1790000000}


def test_anchor_smaller_than_receipt_with_valid_proof_passes(monkeypatch):  # receipt at 7, anchor at 3
    r = _run(monkeypatch, _chain(3, CONS["first_root"]), _proof(7, CONS["second_root"]), [CONS])
    assert r["ok"] is True and r["reason"] == "anchored"


@pytest.mark.parametrize("leaf", [3, 6])
def test_anchor_smaller_than_receipt_does_not_cover_a_later_leaf(monkeypatch, leaf):
    # Audit #232: the anchor of the first 3 leaves can't give a proven-by time to leaf 3 or later.
    r = _run(monkeypatch, _chain(3, CONS["first_root"]), _proof(7, CONS["second_root"], leaf), [CONS])
    assert r == {"ok": False, "reason": "anchor_does_not_cover_leaf", "proven_by": None}


def test_anchor_with_wrong_proof_is_invalid(monkeypatch):
    bad = _vec("041-consistency-wrong-old-root.json")
    forged_root = p.b64u(p.sha256(b"forged"))
    for chain_root, proof_root, doc in [(CONS["second_root"], forged_root, CONS),  # receipt root not in the attested tree
                                        (CONS["second_root"], CONS["first_root"], {**CONS, "proof": CONS["proof"][:-1]}),
                                        (CONS["second_root"], bad["first_root"], bad)]:
        r = _run(monkeypatch, _chain(7, chain_root), _proof(3, proof_root), doc)
        assert r == {"ok": False, "reason": "consistency_proof_invalid", "proven_by": None}


def test_consistency_doc_for_other_sizes_is_rejected():
    from qed_proof.log import check_consistency_doc
    assert check_consistency_doc({**CONS, "first": 2}, 3, 7, CONS["first_root"], CONS["second_root"]) is False
    assert check_consistency_doc({"proof": "x"}, 3, 7, CONS["first_root"], CONS["second_root"]) is False


def test_anchor_without_any_proof_is_required(monkeypatch):
    r = _run(monkeypatch, _chain(7, CONS["second_root"]), _proof(3, CONS["first_root"]))
    assert r["reason"] == "consistency_proof_required"


def test_verify_receipt_fetches_consistency_from_issuer(monkeypatch):
    receipt = json.loads(json.dumps(_vec("016-inclusion-first-leaf.json")))
    receipt["proof"]["anchor"] = {"chain": "eip155:84532", "scheme": "eas", "uid": "0x" + UID.hex(),
                                  "tx_hash": "0x" + "11" * 32, "tree_size": 9}
    keys = {**KEYSET, **KEYS}
    # the chain attests a 9-leaf tree whose root we pretend extends the receipt's 7-leaf tree
    monkeypatch.setattr(A, "_rpc", _chain(9, p.b64u(p.sha256(b"nine"))))
    seen = []

    def fetch(url):
        seen.append(url)
        return None
    rep = verify_receipt(receipt, keys, rpc_url="http://rpc", issuer="https://issuer.example", fetch=fetch)
    assert seen == ["https://issuer.example/v1/log/consistency?first=7&second=9"]
    assert rep.checks["anchor"] == "consistency_proof_required"
    rep = verify_receipt(receipt, keys, rpc_url="http://rpc")
    assert rep.checks["anchor"] == "consistency_proof_required"
