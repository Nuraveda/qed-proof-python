"""Offline (and optionally on-chain) verification of a PoAW receipt (poaw/0.1 and poaw/0.2).

This is a port of ``oss/spec/tools/check.py``'s ``check()`` function, not an import of it — the SDK
is self-contained and carries its own copy of the primitives (``_primitives.py``) and the anchor
check (``_anchor.py``). The conformance suite (``tests/test_conformance.py``) proves the two agree on
every vector in the spec's manifest.
"""
from __future__ import annotations

import functools
import json
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Callable

import jsonschema

from . import _nitro
from . import _primitives as ref
from .log import check_head, consistency_source

__all__ = ["AttestationError", "NitroAttestation", "VerifyReport", "verify_receipt"]

AttestationError = _nitro.AttestationError
NitroAttestation = _nitro.NitroAttestation


@functools.lru_cache(maxsize=None)
def _schema(name: str = "receipt") -> dict:
    text = resources.files("qed_proof").joinpath(f"{name}.schema.json").read_text(encoding="utf-8")
    return json.loads(text)


@functools.lru_cache(maxsize=None)
def _validator(name: str = "receipt") -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(_schema(name))


def _check_policy(policy: Any, pipeline: Any) -> bool:
    """SPEC §15.2: the document is valid, its id and version are the policy's, and its digest is the policy's."""
    return bool(
        isinstance(policy, dict)
        and isinstance(pipeline, dict)
        and not ref.has_float(pipeline)
        and not list(_validator("pipeline").iter_errors(pipeline))
        and pipeline.get("id") == policy.get("pipeline_id")
        and pipeline.get("version") == policy.get("pipeline_version")
        and ref.pipeline_digest(pipeline) == policy.get("digest")
    )


@dataclass(frozen=True)
class VerifyReport:
    """The result of :func:`verify_receipt`. Field names and values mirror ``check.py``'s report dict exactly,
    including the string values a check can take (``"absent"``, ``"not_checked_offline"``, a failure reason)."""

    checks: dict[str, Any]
    valid: bool
    achieved_trust_level: int
    verdict: str | None
    proven_by: int | None = None
    entry_kind: str | None = None  # "change" for a change entry (SPEC §14); None for a receipt
    _anchor_checked: bool = field(default=False, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        """Exactly ``check.py``'s report dict shape: ``{"checks": {...}, "valid", "achieved_trust_level", "verdict"}``,
        plus ``entry_kind`` (only for a change entry) and ``proven_by`` (present, even if null, whenever an on-chain anchor check actually ran — matching the
        reference, which only assigns ``report["proven_by"]`` in that branch)."""
        out: dict[str, Any] = {
            "checks": dict(self.checks),
            "valid": self.valid,
            "achieved_trust_level": self.achieved_trust_level,
            "verdict": self.verdict,
        }
        if self.entry_kind is not None:
            out["entry_kind"] = self.entry_kind
        if self._anchor_checked:
            out["proven_by"] = self.proven_by
        return out


def verify_receipt(
    receipt: dict, keys: dict, rpc_url: str | None = None, pipeline: dict | None = None, *,
    head: Any = None, consistency: Any = None, issuer: str | None = None, fetch: Callable[[str], Any] | None = None,
    nitro_root: bytes | None = None,
) -> VerifyReport:
    """Verify a receipt against a keyset (as returned by ``GET /.well-known/poaw-keys.json`` or
    :meth:`QedProof.get_keys`). With ``rpc_url``, also checks the on-chain anchor (SPEC §8.4); without
    it, an anchored receipt reports ``anchor: "not_checked_offline"``. Change entries (``entry_kind: "change"``,
    SPEC §14) are verified under their own schema and signature domain and carry no claim digest or verdict.
    If the body carries a ``policy``, ``pipeline`` (the pipeline document, SPEC §15.2) is checked against it;
    without ``pipeline`` the ``policy`` check reports ``"not_checked"`` and does not fail the entry. Any doubt fails the check — an
    RPC error, a decode error or a mismatch all give ``"unproven"``-shaped results, never a pass.

    When the anchor's tree size differs from the receipt's proof (SPEC §8.4), a consistency proof connects the two
    roots: pass ``consistency`` (a ``GET /v1/log/consistency`` response, or a list of them), or ``issuer`` (the issuer's
    base URL, from which ``/v1/log/consistency`` is fetched; ``fetch(url) -> dict`` overrides the HTTP GET). With none
    obtainable the anchor reads ``"consistency_proof_required"``; a proof that does not verify reads
    ``"consistency_proof_invalid"``. Pass ``head`` (a signed tree head, SPEC §8.5: bare ``{body, signature}`` or the
    ``GET /v1/log/head`` response) to add a ``head`` check: its signature verifies and the receipt's tree is a prefix of it.

    At ``trust_level >= 3`` the receipt's ``attestation_document`` is checked in full (SPEC §7.1, §10 step 5) against the
    keyset's ``verifier_builds``, and ``checks["attestation"]`` is ``True`` or a reason (``attestation_invalid``,
    ``attestation_chain``, ``pcr_mismatch``, ``statement_mismatch``, ``unknown_build``). A failure never invalidates the
    receipt; it only caps the achieved level. Level 3 is cumulative: it needs level 2 and a passing attestation.
    ``nitro_root`` (DER bytes) replaces the pinned AWS Nitro root and exists for tests only.

    Requires the ``qed-proof[anchor]`` extra when ``rpc_url`` is given.
    """
    report: dict[str, Any] = {"checks": {}}
    c = report["checks"]

    body = receipt.get("body", {}) if isinstance(receipt, dict) else {}
    version = str(body.get("spec_version", ""))
    c["spec_version"] = version.split("/")[0] == "poaw" and version.split("/")[-1].split(".")[0] == "0"
    kind = ref.entry_kind(body)
    is_change = kind == "change"
    # §14: no entry_kind is a receipt, "change" is a change entry, anything else is not an entry this spec defines.
    c["schema"] = (kind is None or is_change) and not list(_validator("change" if is_change else "receipt").iter_errors(receipt))
    c["integers_only"] = not ref.has_float(receipt)

    sig = receipt.get("signature", {}) if isinstance(receipt, dict) else {}
    key = next((k for k in keys.get("keys", []) if k["key_id"] == sig.get("key_id")), None)
    issued = body.get("issued_at", "")
    key_ok = bool(
        key
        and sig.get("key_id") == body.get("issuer", {}).get("key_id")
        and ref.key_id(ref.b64u_decode(key["public_key"])) == key["key_id"]
        and key["valid_from"] <= issued
        and (key.get("revoked_at") is None or issued < key["revoked_at"])
    )
    c["key"] = key_ok
    domain = ref.CHANGE_SIG_DOMAIN if is_change else ref.SIG_DOMAIN
    c["signature"] = bool(
        key_ok and ref.verify_signature(ref.b64u_decode(key["public_key"]), body, sig.get("value", ""), domain))
    if not is_change:  # a change entry has no claim (§14.1)
        claim = body.get("claim", {})
        c["claim_digest"] = isinstance(claim, dict) and claim.get("claim_digest") == ref.claim_digest(claim)

    proof = receipt.get("proof")
    if proof is None:
        c["inclusion"] = "absent"
    else:
        root = ref.root_from_inclusion(
            proof["leaf_index"], proof["tree_size"], ref.leaf_hash(receipt),
            [ref.b64u_decode(h) for h in proof["inclusion"]],
        )
        c["inclusion"] = root is not None and ref.b64u(root) == proof["root_hash"]

    get_consistency = consistency_source(consistency, issuer, fetch)
    proven_by = None
    anchor_checked = False
    if not (proof and proof.get("anchor")):
        c["anchor"] = "absent"
    elif not rpc_url:
        c["anchor"] = "not_checked_offline"
    else:
        try:
            from . import _anchor
        except ImportError as exc:
            raise ImportError(
                "rpc_url was given but the 'anchor' extra is not installed: pip install 'qed-proof[anchor]'"
            ) from exc
        a = _anchor.check_anchor(proof, keys, rpc_url, ref.b64u_decode, get_consistency)
        c["anchor"] = True if a["ok"] else a["reason"]
        proven_by = a["proven_by"]
        anchor_checked = True

    # §7.1 / §10 step 5: at trust_level >= 3 the attestation is checked in full. A failure never invalidates the receipt
    # (it is still a signed L1/L2 receipt); it only caps the achieved level, and `attestation` carries the reason.
    tl = body.get("trust_level")
    if not is_change and c["schema"] and isinstance(tl, int) and not isinstance(tl, bool) and tl >= 3:
        try:
            _nitro.verify_enclave_receipt(receipt, keys.get("verifier_builds"), root_der=nitro_root)
            c["attestation"] = True
        except _nitro.AttestationError as e:
            c["attestation"] = e.reason
        except Exception:  # anything unforeseen is unproven, never a pass
            c["attestation"] = "attestation_invalid"

    # §15.2: only present when the body carries a policy. Without the pipeline document it is "not_checked".
    policy = body.get("policy")
    if policy is not None:
        c["policy"] = "not_checked" if pipeline is None else _check_policy(policy, pipeline)

    if head is not None:  # §8.5: only when the caller supplied a signed tree head
        h = check_head(head, proof, keys, get_consistency)
        c["head"] = True if h["ok"] else h["reason"]

    required = ("spec_version", "schema", "integers_only", "key", "signature") + (() if is_change else ("claim_digest",))
    valid = (all(c[k] is True for k in required) and c["inclusion"] in (True, "absent")
             and c.get("policy", True) in (True, "not_checked")
             and c.get("head", True) is True)
    # SPEC §7: report the ACHIEVED level. L2 needs inclusion AND an anchor verified on-chain (rpc_url given); offline
    # the ceiling is 1.
    achieved = (2 if c["inclusion"] is True and c["anchor"] is True else 1) if valid else 0
    # §7.1: levels are cumulative, so level 3 needs level 2 (inclusion + a verified anchor) and every attestation rule.
    if valid and c.get("attestation") is True and achieved == 2:
        achieved = 3
    verdict = body.get("verdict", {}).get("value") if valid and not is_change else None

    return VerifyReport(
        checks=c, valid=valid, achieved_trust_level=achieved, verdict=verdict,
        proven_by=proven_by, entry_kind="change" if is_change else None, _anchor_checked=anchor_checked,
    )
