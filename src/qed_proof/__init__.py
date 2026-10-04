"""qed-proof: the Python SDK for QED Proof.

    from qed_proof import QedProof, actions, verify_receipt

    qp = QedProof(api_key="qed_sk_...")
    claim = qp.submit_claim(actions.github_commit_push(target="owner/repo", sha="...", branch="main"),
                            agent_id="my-agent")
    result = qp.wait_for_verdict(claim.claim_id)
    receipt = qp.get_receipt(result.receipt_id)
    report = verify_receipt(receipt, keys=qp.get_keys())
"""
from __future__ import annotations

from . import actions
from .actions import Action
from .client import (
    AsyncQedProof,
    ClaimPage,
    ClaimResult,
    QedProof,
    QedProofError,
    QedProofRateLimited,
    QedProofTimeout,
)
from ._primitives import pipeline_digest
from .log import (
    AnchorPage,
    ConsistencyProof,
    EntryPage,
    InclusionProof,
    LogAnchor,
    LogEntry,
    LogHead,
    SignedTreeHead,
    TreeHeadReport,
    verify_consistency,
    verify_tree_head,
)
from .verify import AttestationError, NitroAttestation, VerifyReport, verify_receipt

__version__ = "0.4.0"

__all__ = [
    "AttestationError",
    "NitroAttestation",
    "AnchorPage",
    "ConsistencyProof",
    "EntryPage",
    "InclusionProof",
    "LogAnchor",
    "LogEntry",
    "LogHead",
    "SignedTreeHead",
    "TreeHeadReport",
    "verify_consistency",
    "verify_tree_head",
    "Action",
    "actions",
    "AsyncQedProof",
    "ClaimPage",
    "ClaimResult",
    "QedProof",
    "QedProofError",
    "QedProofRateLimited",
    "QedProofTimeout",
    "VerifyReport",
    "verify_receipt",
    "pipeline_digest",
    "__version__",
]
