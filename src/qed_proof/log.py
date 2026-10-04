"""The public Merkle log (SPEC §8.4-§8.6): signed tree heads, consistency proofs, and typed models for the
issuer's free, unauthenticated ``/v1/log/*`` endpoints.

Verification here is ported from ``oss/spec/tools/check.py``. Any doubt gives a failing check, never a pass.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from . import _primitives as ref

__all__ = [
    "TreeHeadReport", "verify_tree_head", "verify_consistency",
    "LogAnchor", "SignedTreeHead", "LogHead", "ConsistencyProof", "InclusionProof",
    "AnchorPage", "LogEntry", "EntryPage",
]


# --- verification ------------------------------------------------------------------------------
@dataclass(frozen=True)
class TreeHeadReport:
    """Result of :func:`verify_tree_head`: ``checks`` has ``shape``, ``key`` and ``signature`` (all bool)."""

    valid: bool
    checks: dict[str, bool]


def _key_valid(key: dict | None, key_id: Any, issued: str) -> bool:
    return bool(
        key
        and key.get("key_id") == key_id
        and ref.key_id(ref.b64u_decode(key["public_key"])) == key["key_id"]
        and key["valid_from"] <= issued
        and (key.get("revoked_at") is None or issued < key["revoked_at"])
    )


def verify_tree_head(head: Any, keys: dict) -> TreeHeadReport:
    """SPEC §8.5: exactly the four body fields with an integer ``tree_size``, a key valid at ``issued_at``, and a
    signature under the tree-head domain. Accepts a bare ``{body, signature}``, a :class:`SignedTreeHead`, a
    :class:`LogHead`, or the raw ``GET /v1/log/head`` response."""
    if isinstance(head, LogHead):
        head = head.tree_head.raw
    elif isinstance(head, SignedTreeHead):
        head = head.raw
    doc = head.get("tree_head", head) if isinstance(head, dict) else None
    body = doc.get("body") if isinstance(doc, dict) else None
    sig = doc.get("signature") if isinstance(doc, dict) else None
    sig = sig if isinstance(sig, dict) else {}
    shape = bool(
        isinstance(body, dict)
        and set(body) == set(ref.TREE_HEAD_FIELDS)
        and isinstance(body["tree_size"], int) and not isinstance(body["tree_size"], bool) and body["tree_size"] >= 0
        and all(isinstance(body[k], str) for k in ("log_id", "root_hash", "issued_at"))
        and sig.get("alg") == "Ed25519"
    )
    key_ok = sig_ok = False
    if shape:
        key = next((k for k in (keys or {}).get("keys", []) if k.get("key_id") == sig.get("key_id")), None)
        try:
            key_ok = _key_valid(key, sig.get("key_id"), body["issued_at"])
            sig_ok = bool(key_ok and ref.verify_tree_head(ref.b64u_decode(key["public_key"]), body, sig.get("value", "")))
        except Exception:  # undecodable key or signature: unproven, never a pass
            key_ok = sig_ok = False
    return TreeHeadReport(valid=shape and key_ok and sig_ok, checks={"shape": shape, "key": key_ok, "signature": sig_ok})


def _bytes(x: str | bytes) -> bytes:
    return ref.b64u_decode(x) if isinstance(x, str) else bytes(x)


def verify_consistency(m: int, n: int, old_root: str | bytes, new_root: str | bytes, proof: list[str | bytes]) -> bool:
    """RFC 9162 §2.1.4.2: ``proof`` shows the size-``m`` tree with root ``old_root`` is a prefix of the size-``n`` tree
    with root ``new_root``. Roots and proof nodes may be base64url strings or raw bytes. The roots must come from your
    own trusted sources (a receipt, a signed head, an attestation), never from the consistency response itself."""
    try:
        return ref.verify_consistency(m, n, _bytes(old_root), _bytes(new_root), [_bytes(p) for p in proof])
    except Exception:
        return False


def check_consistency_doc(doc: Any, first: int, second: int, old_root: str, new_root: str) -> bool:
    """Does ``doc`` (shaped like ``GET /v1/log/consistency``) prove old -> new for exactly these sizes?"""
    if isinstance(doc, ConsistencyProof):
        doc = doc.raw
    if not isinstance(doc, dict) or doc.get("first") != first or doc.get("second") != second:
        return False
    proof = doc.get("proof")
    if not isinstance(proof, list):
        return False
    return verify_consistency(first, second, old_root, new_root, proof)


def _default_fetch(url: str) -> Any:
    req = urllib.request.Request(url, headers={"accept": "application/json", "user-agent": "qed-proof-py"})
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 - issuer URL is caller-supplied by design
        return json.loads(r.read())


def consistency_source(
    consistency: Any = None, issuer: str | None = None, fetch: Callable[[str], Any] | None = None
) -> Callable[[int, int], Any]:
    """Return ``get(first, second)``: a supplied consistency document for those sizes, else the issuer's
    ``GET {issuer}/v1/log/consistency?first=&second=`` (via ``fetch``, default a plain GET), else ``None``."""
    if consistency is None:
        supplied: list[Any] = []
    elif isinstance(consistency, (list, tuple)):
        supplied = list(consistency)
    else:
        supplied = [consistency]
    supplied = [d.raw if isinstance(d, ConsistencyProof) else d for d in supplied]
    do_fetch = fetch or _default_fetch

    def get(first: int, second: int) -> Any:
        for d in supplied:
            if isinstance(d, dict) and d.get("first") == first and d.get("second") == second:
                return d
        if issuer:
            try:
                return do_fetch(f"{issuer.rstrip('/')}/v1/log/consistency?first={first}&second={second}")
            except Exception:
                return None
        return None

    return get


def check_head(head: Any, proof: dict | None, keys: dict, get_consistency: Callable[[int, int], Any]) -> dict:
    """SPEC §8.5 + §8.4: the head's signature verifies and, when the receipt has a proof, the receipt's tree is a prefix of
    the head's. Returns ``{"ok": bool, "reason": str, "checks": {...}}``."""
    r = verify_tree_head(head, keys)
    if not r.valid:
        return {"ok": False, "reason": "head_signature_invalid", "checks": r.checks}
    if isinstance(head, LogHead):
        head = head.tree_head.raw
    elif isinstance(head, SignedTreeHead):
        head = head.raw
    hb = head.get("tree_head", head)["body"]
    if proof is None:
        return {"ok": True, "reason": "head_signed", "checks": r.checks}
    if hb["log_id"] != proof["log_id"]:
        return {"ok": False, "reason": "log_mismatch", "checks": r.checks}
    m, n = proof["tree_size"], hb["tree_size"]
    if m > n:
        return {"ok": False, "reason": "head_older_than_receipt", "checks": r.checks}
    if m == n:
        same = hb["root_hash"] == proof["root_hash"]
        return {"ok": same, "reason": "head_consistent" if same else "root_mismatch", "checks": r.checks}
    doc = get_consistency(m, n)
    if doc is None:
        return {"ok": False, "reason": "consistency_proof_required", "checks": r.checks}
    ok = check_consistency_doc(doc, m, n, proof["root_hash"], hb["root_hash"])
    return {"ok": ok, "reason": "head_consistent" if ok else "not_consistent", "checks": r.checks}


# --- models for the /v1/log/* responses (SPEC §8.6) --------------------------------------------
@dataclass(frozen=True)
class LogAnchor:
    """An on-chain anchor of a tree head (EAS attestation)."""

    chain: str
    scheme: str
    uid: str
    tx_hash: str
    tree_size: int
    root_hash: str
    block_number: int | None = None
    block_time: int | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> "LogAnchor":
        return cls(chain=d["chain"], scheme=d["scheme"], uid=d["uid"], tx_hash=d["tx_hash"],
                   tree_size=d["tree_size"], root_hash=d["root_hash"],
                   block_number=d.get("block_number"), block_time=d.get("block_time"), raw=d)


@dataclass(frozen=True)
class SignedTreeHead:
    """A signed tree head (SPEC §8.5). Check it with :func:`verify_tree_head`."""

    log_id: str
    tree_size: int
    root_hash: str
    issued_at: str
    key_id: str
    signature: str
    raw: dict[str, Any] = field(default_factory=dict, repr=False)  # the bare {body, signature} object

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> "SignedTreeHead":
        b, s = d["body"], d["signature"]
        return cls(log_id=b["log_id"], tree_size=b["tree_size"], root_hash=b["root_hash"], issued_at=b["issued_at"],
                   key_id=s["key_id"], signature=s["value"], raw=d)


@dataclass(frozen=True)
class LogHead:
    """``GET /v1/log/head``: the signed head and the latest landed anchor, if any."""

    tree_head: SignedTreeHead
    anchor: LogAnchor | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> "LogHead":
        a = d.get("anchor")
        return cls(tree_head=SignedTreeHead._from_dict(d["tree_head"]),
                   anchor=LogAnchor._from_dict(a) if a else None, raw=d)


@dataclass(frozen=True)
class ConsistencyProof:
    """``GET /v1/log/consistency``. Verify with :func:`verify_consistency` using roots you trust, not these."""

    log_id: str
    first: int
    second: int
    first_root: str
    second_root: str
    proof: list[str]
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> "ConsistencyProof":
        return cls(log_id=d["log_id"], first=d["first"], second=d["second"], first_root=d["first_root"],
                   second_root=d["second_root"], proof=list(d["proof"]), raw=d)


@dataclass(frozen=True)
class InclusionProof:
    """``GET /v1/log/proof``: an audit path for one leaf."""

    log_id: str
    leaf_index: int
    tree_size: int
    leaf_hash: str
    root_hash: str
    inclusion: list[str]
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> "InclusionProof":
        return cls(log_id=d["log_id"], leaf_index=d["leaf_index"], tree_size=d["tree_size"], leaf_hash=d["leaf_hash"],
                   root_hash=d["root_hash"], inclusion=list(d["inclusion"]), raw=d)


@dataclass(frozen=True)
class AnchorPage:
    """``GET /v1/log/anchors``, newest first. ``next`` is the ``before`` value for the next page, or ``None``."""

    anchors: list[LogAnchor]
    next: int | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> "AnchorPage":
        return cls(anchors=[LogAnchor._from_dict(a) for a in d.get("anchors", [])], next=d.get("next"), raw=d)


@dataclass(frozen=True)
class LogEntry:
    """One ledger row: hashes and time only; the log does not list receipt ids."""

    leaf_index: int
    leaf_hash: str
    created_at: str


@dataclass(frozen=True)
class EntryPage:
    """``GET /v1/log/entries``, ascending. ``next`` is the ``start`` value for the next page, or ``None``."""

    tree_size: int
    entries: list[LogEntry]
    next: int | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> "EntryPage":
        return cls(tree_size=d["tree_size"],
                   entries=[LogEntry(e["leaf_index"], e["leaf_hash"], e["created_at"]) for e in d.get("entries", [])],
                   next=d.get("next"), raw=d)


def _params(**kw: Any) -> dict[str, Any]:
    return {k: v for k, v in kw.items() if v is not None}
