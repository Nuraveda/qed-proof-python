"""TypedDicts for the poaw/0.1 receipt shape, hand-derived from ``receipt.schema.json``.

These describe the JSON a receipt deserializes to (``json.load`` output) — plain dicts, not a
validating model. ``jsonschema`` (via :func:`qed_proof.verify.verify_receipt`) is the source of
truth for validity; these types are for editor/typing convenience only.

``tests/test_types.py`` walks the vendored schema and asserts every ``required`` property of every
object in it appears as a key here, so the two can't silently drift apart.
"""
from __future__ import annotations

from typing import Literal, TypedDict

VerdictValue = Literal["verified", "late", "mismatch", "failed", "unverifiable"]
ReasonCode = Literal[
    "not_found", "content_mismatch", "target_mismatch", "observed_after_tolerance",
    "no_connection", "permission_denied", "rate_limited", "destination_unavailable",
    "unsupported_action", "claim_ambiguous", "verifier_error",
]


class Erc8004(TypedDict, total=False):
    chain: str
    registry: str
    agent_id: str


class Agent(TypedDict, total=False):
    id: str
    erc8004: Erc8004


class Issuer(TypedDict, total=False):
    key_id: str
    name: str


class Claim(TypedDict, total=False):
    action: str
    target: str
    params: dict
    claimed_at: str
    client_claim_id: str
    claim_digest: str


class VerifierRef(TypedDict, total=False):
    id: str
    version: str
    code_hash: str


class Observation(TypedDict, total=False):
    verifier: VerifierRef
    observed_at: str
    deadline_at: str
    attempts: int
    facts: dict


class VerdictBlock(TypedDict, total=False):
    value: VerdictValue
    reason_code: ReasonCode


class Attestation(TypedDict, total=False):
    type: str
    document_sha256: str


class ReceiptBody(TypedDict, total=False):
    spec_version: str
    receipt_id: str
    issued_at: str
    issuer: Issuer
    agent: Agent
    operator: str
    claim: Claim
    observation: Observation
    verdict: VerdictBlock
    trust_level: int
    attestation: Attestation
    supersedes: str


class Signature(TypedDict, total=False):
    alg: Literal["Ed25519"]
    key_id: str
    value: str


class Anchor(TypedDict, total=False):
    chain: str
    scheme: Literal["eas"]
    uid: str
    tx_hash: str
    tree_size: int


class Proof(TypedDict, total=False):
    log_id: str
    leaf_index: int
    tree_size: int
    root_hash: str
    inclusion: list[str]
    anchor: Anchor


class Receipt(TypedDict, total=False):
    body: ReceiptBody
    signature: Signature
    proof: Proof
    attestation_document: str


__all__ = [
    "Agent", "Anchor", "Attestation", "Claim", "Erc8004", "Issuer", "Observation", "Proof",
    "Receipt", "ReceiptBody", "ReasonCode", "Signature", "VerdictBlock", "VerdictValue", "VerifierRef",
]
