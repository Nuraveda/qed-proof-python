"""Public log: client methods against a mocked transport, head verification and the receipt-level consistency paths."""
from __future__ import annotations

import json

import httpx
import pytest

from qed_proof import AsyncQedProof, QedProof, QedProofError, verify_receipt
from qed_proof.client import DEFAULT_BASE_URL

VECTORS = __import__("pathlib").Path(__file__).parent / "vectors"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text())
KEYSET = json.loads((VECTORS / MANIFEST["keyset"]).read_text())


def _vec(name):
    return json.loads((VECTORS / name).read_text())


HEAD = _vec("036-tree-head-valid.json")
CONS = _vec("040-consistency-valid.json")
ANCHOR = {"chain": "eip155:84532", "scheme": "eas", "uid": "0x" + "77" * 32, "tx_hash": "0x" + "11" * 32,
          "tree_size": 7, "root_hash": HEAD["body"]["root_hash"], "block_number": 47309207, "block_time": 1790000000}


def _routes(request: httpx.Request) -> httpx.Response:
    assert "authorization" not in request.headers, "log endpoints are public: the API key must not be sent"
    path, q = request.url.path, dict(request.url.params)
    if path == "/v1/log/head":
        return httpx.Response(200, json={"tree_head": HEAD, "anchor": ANCHOR})
    if path == "/v1/log/consistency":
        assert q == {"first": "3", "second": "7"}
        return httpx.Response(200, json=CONS)
    if path == "/v1/log/proof":
        return httpx.Response(200, json={"log_id": "L", "leaf_index": int(q["leaf_index"]), "tree_size": int(q.get("tree_size", 7)),
                                         "leaf_hash": "lh", "root_hash": "rh", "inclusion": ["a", "b"], "_q": q})
    if path == "/v1/log/anchors":
        return httpx.Response(200, json={"anchors": [ANCHOR], "next": 7, "_q": q})
    if path == "/v1/log/entries":
        return httpx.Response(200, json={"tree_size": 7, "entries": [{"leaf_index": 0, "leaf_hash": "h0", "created_at": "t"}],
                                         "next": 1, "_q": q})
    return httpx.Response(404, json={"detail": "nope"})


def _client(handler=_routes) -> QedProof:
    return QedProof(api_key="qed_sk_secret", http_client=httpx.Client(transport=httpx.MockTransport(handler), base_url=DEFAULT_BASE_URL))


def _aclient(handler=_routes) -> AsyncQedProof:
    return AsyncQedProof(api_key="qed_sk_secret",
                         http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=DEFAULT_BASE_URL))


def test_log_head_typed_and_verifiable():
    from qed_proof import verify_tree_head
    h = _client().log_head()
    assert h.tree_head.tree_size == 7 and h.tree_head.root_hash == HEAD["body"]["root_hash"]
    assert h.anchor is not None and h.anchor.block_number == 47309207
    assert verify_tree_head(h, KEYSET).valid is True


def test_log_head_without_anchor_and_without_api_key():
    def handler(request):
        assert "authorization" not in request.headers
        return httpx.Response(200, json={"tree_head": HEAD, "anchor": None})
    qp = QedProof(http_client=httpx.Client(transport=httpx.MockTransport(handler)))  # no key at all
    assert qp.log_head().anchor is None


def test_log_consistency_proof_verifies():
    from qed_proof import verify_consistency
    c = _client().log_consistency(3, 7)
    assert (c.first, c.second) == (3, 7)
    assert verify_consistency(c.first, c.second, c.first_root, c.second_root, c.proof)


def test_log_proof_params():
    p = _client().log_proof(2)
    assert p.leaf_index == 2 and p.inclusion == ["a", "b"] and p.raw["_q"] == {"leaf_index": "2"}
    assert _client().log_proof(2, tree_size=5).raw["_q"] == {"leaf_index": "2", "tree_size": "5"}


def test_log_anchors_and_entries_params():
    a = _client().log_anchors()
    assert a.next == 7 and a.anchors[0].uid == ANCHOR["uid"] and a.raw["_q"] == {"limit": "20"}
    assert _client().log_anchors(limit=5, before=9).raw["_q"] == {"limit": "5", "before": "9"}
    e = _client().log_entries()
    assert e.entries[0].leaf_hash == "h0" and e.next == 1 and e.raw["_q"] == {"limit": "50"}
    assert _client().log_entries(start=10, limit=3).raw["_q"] == {"start": "10", "limit": "3"}


def test_log_error_raises():
    def handler(request):
        return httpx.Response(400, json={"detail": "first > second"})
    with pytest.raises(QedProofError) as ei:
        _client(handler).log_consistency(9, 3)
    assert ei.value.status_code == 400


async def test_async_log_methods():
    qp = _aclient()
    assert (await qp.log_head()).tree_head.tree_size == 7
    assert (await qp.log_consistency(3, 7)).proof == CONS["proof"]
    assert (await qp.log_proof(1, 7)).leaf_index == 1
    assert (await qp.log_anchors(limit=2)).anchors[0].tree_size == 7
    assert (await qp.log_entries(start=0)).tree_size == 7


# --- head check on a receipt (SPEC §8.5) -----------------------------------------------------------
def _receipt_with_proof(tree_size, root_hash):
    r = json.loads(json.dumps(_vec("001-valid-verified.json")))
    return r, {"log_id": HEAD["body"]["log_id"], "tree_size": tree_size, "root_hash": root_hash}


def _check_head(proof, head=HEAD, consistency=None, **kw):
    from qed_proof.log import check_head, consistency_source
    return check_head(head, proof, KEYSET, consistency_source(consistency, **kw))


def test_head_check_equal_sizes_needs_equal_roots():
    ok = _check_head({"log_id": HEAD["body"]["log_id"], "tree_size": 7, "root_hash": HEAD["body"]["root_hash"]})
    assert ok["ok"] and ok["reason"] == "head_consistent"
    bad = _check_head({"log_id": HEAD["body"]["log_id"], "tree_size": 7, "root_hash": CONS["first_root"]})
    assert not bad["ok"] and bad["reason"] == "root_mismatch"


def test_head_check_consistency_paths():
    proof = {"log_id": HEAD["body"]["log_id"], "tree_size": 3, "root_hash": CONS["first_root"]}
    assert _check_head(proof, consistency=CONS)["reason"] == "head_consistent"
    assert _check_head(proof)["reason"] == "consistency_proof_required"
    wrong = {**CONS, "proof": CONS["proof"][:-1]}
    assert _check_head(proof, consistency=wrong)["reason"] == "not_consistent"
    fetched = _check_head(proof, issuer="https://issuer.example", fetch=lambda url: CONS if url.endswith("first=3&second=7") else None)
    assert fetched["ok"]


def test_head_check_rejections():
    assert _check_head({"log_id": "other", "tree_size": 3, "root_hash": "x"})["reason"] == "log_mismatch"
    assert _check_head({"log_id": HEAD["body"]["log_id"], "tree_size": 9, "root_hash": "x"})["reason"] == "head_older_than_receipt"
    tampered = _vec("037-tree-head-tampered.json")
    assert _check_head(None, head=tampered)["reason"] == "head_signature_invalid"
    assert _check_head(None)["reason"] == "head_signed"


def test_verify_receipt_head_check_end_to_end():
    receipt = _vec("016-inclusion-first-leaf.json")  # a 7-leaf tree, but not the log HEAD commits to (different root)
    assert "head" not in verify_receipt(receipt, KEYSET).checks
    rep = verify_receipt(receipt, KEYSET, head=HEAD)
    assert rep.checks["head"] == "root_mismatch" and rep.valid is False and rep.achieved_trust_level == 0
    rep = verify_receipt(receipt, KEYSET, head={"tree_head": _vec("037-tree-head-tampered.json"), "anchor": None})
    assert rep.checks["head"] == "head_signature_invalid" and rep.valid is False
    other = {**receipt, "proof": {**receipt["proof"], "log_id": "someone-else"}}
    assert verify_receipt(other, KEYSET, head=HEAD).checks["head"] == "log_mismatch"
