# Changelog

All notable changes to `qed-proof` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.1] - 2026-10-08

### Fixed

- An anchor of a **smaller** tree than the receipt's proof no longer counts as anchoring a receipt appended after it.
  The check now requires `proof.leaf_index < anchor.tree_size` and otherwise reports `anchor_does_not_cover_leaf`
  (SPEC §8.4). Before, a valid consistency proof alone was accepted, so such a receipt got a proven-by time from
  before it existed. Receipts from an honest issuer are unaffected: it attaches an anchor that covers the receipt.

## [0.4.0] - 2026-10-04

### Added

- Trust level 3 (SPEC §7.1, §10 step 5): at `trust_level >= 3`, `verify_receipt` checks the receipt's AWS Nitro Enclaves
  attestation document offline (strict CBOR, COSE ES384, X.509 chain to the pinned AWS Nitro root, PCR0 = `code_hash`,
  user_data = statement digest, `document_sha256`, and a published build in the keyset's `verifier_builds`). The result is
  `checks["attestation"]` (`True` or a reason). `achieved_trust_level` is 3 only when level 2 is achieved and the
  attestation passes; a failed attestation never invalidates the receipt, it only caps the level.
- New exports `AttestationError` and `NitroAttestation`; `verify_receipt(..., nitro_root=)` is a test-only trust-anchor override.

## [0.3.0] - 2026-10-04

Adds the free public Merkle log: read the log and check signed tree heads and consistency proofs.

### Added

- Public Merkle log client methods, sync and async, no API key sent: `log_head()`, `log_consistency(first, second)`,
  `log_proof(leaf_index, tree_size=None)`, `log_anchors(limit=20, before=None)`, `log_entries(start=None, limit=50)`,
  returning typed models (`LogHead`, `ConsistencyProof`, `InclusionProof`, `AnchorPage`, `EntryPage`).
- `verify_tree_head(head, keys)` (SPEC §8.5) and `verify_consistency(m, n, old_root, new_root, proof)` (RFC 9162 §2.1.4.2).
- `verify_receipt(..., consistency=, issuer=, fetch=)`: when an anchor's tree size differs from the receipt's proof, a
  consistency proof (supplied, or fetched from the issuer's `/v1/log/consistency`) connects the roots. The anchor check
  reports `consistency_proof_required` when none is obtainable and `consistency_proof_invalid` when it does not verify.
- `verify_receipt(..., head=)` adds a `head` check: the signed tree head verifies and the receipt's tree is a prefix of it.
- `QedProof.verify` / `AsyncQedProof.verify` accept `head=` and `consistency=` and fetch proofs from the client's `base_url`.

## [0.2.0] - 2026-10-01

### Added

- `verify_receipt` verifies **change entries** (`entry_kind: "change"`, SPEC §14): signed log entries for a change at a
  destination that no claim explained, signed under their own domain. The report has `entry_kind="change"`, no verdict and
  no `claim_digest` check.
- `verify_receipt(receipt, keys, pipeline=...)`: pass the pipeline document to check a receipt's or change entry's
  `policy` (SPEC §15.2). The report gains a `policy` check: `True`, `False`, or `"not_checked"` when no document is given.
- `pipeline_digest(pipeline)`.

### Changed

- Accepts `poaw/0.1` and `poaw/0.2` receipts. Reports for receipts that use nothing new are unchanged.

## [0.1.3] - 2026-10-01

### Changed

- The source repository moved to `github.com/Nuraveda/qed-proof-python` (the old URL redirects). The
  package's Source link now points there. No code changes.

## [0.1.2] - 2026-09-28

### Fixed

- `get_claim` and `get_receipt` (sync and async) URL-encode the id, so an id containing `/`, `?` or `#` can't change the request path.

## [0.1.1] - 2026-09-27

The first version published to PyPI. 0.1.0 was tagged on the public repository but never
published; 0.1.1 has the same library code, released through the gated trusted-publishing workflow.

## [0.1.0] - 2026-09-27 (never published)

Initial release.

### Added

- `QedProof` / `AsyncQedProof` clients: `submit_claim`, `get_claim`, `wait_for_verdict`, `list_claims`,
  `iter_claims`, `get_receipt`, `get_keys`, and a `verify` convenience method.
- `verify_receipt(receipt, keys, rpc_url=None) -> VerifyReport`: a self-contained, offline-capable
  port of the PoAW reference checker (`check.py`, `anchor_check.py` and the `poaw_core` primitives).
  Reproduces all 20 spec conformance vectors exactly.
- Typed action helpers in `qed_proof.actions` for `github.commit.push`, `github.pr.open`,
  `github.checks.pass`, `x.post.publish`, `slack.message.post` and `http.url.status`.
- `qed_proof.types`: TypedDicts for the receipt shape, checked against the vendored JSON Schema.
- Optional `anchor` extra (`eth-abi`, `eth-hash`) for checking a receipt's on-chain EAS anchor against
  a JSON-RPC endpoint.
- Errors: `QedProofError`, `QedProofRateLimited` (exposes `retry_after`), `QedProofTimeout`.

[Unreleased]: https://github.com/Nuraveda/qed-proof-python/compare/sdk-python-v0.4.1...HEAD
[0.4.1]: https://github.com/Nuraveda/qed-proof-python/compare/sdk-python-v0.4.0...sdk-python-v0.4.1
[0.4.0]: https://github.com/Nuraveda/qed-proof-python/compare/sdk-python-v0.3.0...sdk-python-v0.4.0
[0.3.0]: https://github.com/Nuraveda/qed-proof-python/compare/sdk-python-v0.2.0...sdk-python-v0.3.0
[0.2.0]: https://github.com/Nuraveda/qed-proof-python/compare/sdk-python-v0.1.3...sdk-python-v0.2.0
[0.1.3]: https://github.com/Nuraveda/qed-proof-python/compare/sdk-python-v0.1.2...sdk-python-v0.1.3
[0.1.2]: https://github.com/Nuraveda/qed-proof-python/compare/sdk-python-v0.1.1...sdk-python-v0.1.2
[0.1.1]: https://github.com/Nuraveda/qed-proof-python/compare/sdk-python-v0.1.0...sdk-python-v0.1.1
[0.1.0]: https://github.com/Nuraveda/qed-proof-python/releases/tag/sdk-python-v0.1.0
