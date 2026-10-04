"""Ported, not imported: the poaw/0.1 and poaw/0.2 receipt primitives (SPEC.md sections 3, 5 and 8).

This is a line-for-line port of ``oss/core-python/src/poaw_core/__init__.py`` from the QED Proof
monorepo, trimmed to what a *verifier* needs (no tree-building or proof-generation helpers, since
the SDK only checks receipts and heads it is handed). Keep this in sync with the reference by hand: the
conformance suite in ``tests/test_conformance.py`` is what actually proves it matches.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SPEC_VERSION = "poaw/0.1"  # what an issuer says when it uses nothing introduced in 0.2 (SPEC §16)
SPEC_VERSION_V02 = "poaw/0.2"  # required when a body carries `policy`, and for every change entry
SIG_DOMAIN = b"POAW-RECEIPT-V0\n"
CHANGE_SIG_DOMAIN = b"POAW-CHANGE-V0\n"  # §5.1: a change entry is signed under its own domain
TREE_HEAD_SIG_DOMAIN = b"POAW-TREE-HEAD-V0\n"  # §8.5: a signed tree head, so it can never verify as a receipt or change
TREE_HEAD_FIELDS = ("log_id", "tree_size", "root_hash", "issued_at")


# --- encoding (SPEC §3) ------------------------------------------------------------------------
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jcs(obj: Any) -> bytes:
    return rfc8785.dumps(obj)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def has_float(obj: Any) -> bool:
    """SPEC §3: receipts carry integers only."""
    if isinstance(obj, bool):
        return False
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(has_float(v) for v in obj.values())
    if isinstance(obj, list):
        return any(has_float(v) for v in obj)
    return False


# --- keys + signatures (SPEC §5) ---------------------------------------------------------------
def key_id(pk_raw: bytes) -> str:
    return "ed25519:" + b64u(sha256(pk_raw))


def verify_signature(pk_raw: bytes, body: dict, sig_value: str, domain: bytes = SIG_DOMAIN) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk_raw).verify(b64u_decode(sig_value), domain + jcs(body))
        return True
    except (InvalidSignature, ValueError):
        return False


def entry_kind(body: Any) -> str | None:
    """A body without `entry_kind` is a receipt (None). `"change"` is a change entry. Anything else is unknown."""
    return body.get("entry_kind") if isinstance(body, dict) else None


def pipeline_digest(pipeline: dict) -> str:
    """SPEC §15.2: base64url(SHA-256(JCS(pipeline document))), the same construction as claim_digest."""
    return b64u(sha256(jcs(pipeline)))


def claim_digest(claim: dict) -> str:
    stripped = {k: v for k, v in claim.items() if k != "claim_digest"}
    return b64u(sha256(jcs(stripped)))


# --- Merkle log, RFC 6962 (SPEC §8) -------------------------------------------------------------
def leaf_hash(receipt: dict) -> bytes:
    return sha256(b"\x00" + jcs({"body": receipt["body"], "signature": receipt["signature"]}))


def _node(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def root_from_inclusion(index: int, size: int, leaf: bytes, path: list[bytes]) -> bytes | None:
    """RFC 9162 §2.1.3.2 audit-path verification. Returns the computed root, or None if the path is malformed."""
    if index >= size:
        return None
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def verify_tree_head(pk_raw: bytes, body: dict, sig_value: str) -> bool:
    """True iff `body` has exactly the §8.5 fields and `sig_value` signs it under the tree-head domain."""
    if not isinstance(body, dict) or set(body) != set(TREE_HEAD_FIELDS):
        return False
    if not isinstance(body["tree_size"], int) or isinstance(body["tree_size"], bool) or body["tree_size"] < 0:
        return False
    return verify_signature(pk_raw, body, sig_value, TREE_HEAD_SIG_DOMAIN)


def _pow2(n: int) -> bool:
    return n > 0 and n & (n - 1) == 0


def verify_consistency(m: int, n: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2. True iff `proof` shows the size-m tree (old_root) is a prefix of the size-n tree (new_root)."""
    if not 0 < m <= n:
        return False
    if m == n:
        return not proof and old_root == new_root
    if not proof:
        return False
    path = list(proof)
    if _pow2(m):
        path = [old_root] + path
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = _node(c, fr), _node(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root
