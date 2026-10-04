# qed-proof

Copyright 2026 Nuraveda Lab

Python SDK for [QED Proof](https://docs.qedproof.site): submit a claim about work your agent did,
get back an independently-verified receipt, and check that receipt locally — with no further call
to QED Proof beyond fetching public keys (and, optionally, a public chain RPC for the on-chain
anchor).

A receipt verifies identically here, in the TypeScript SDK, and in the spec's own reference
`check.py` — this package's `verify_receipt` is a line-for-line port of that tool, proven against
the same 20-vector conformance suite.

## Install

```bash
pip install qed-proof
# or, if you'll check an on-chain anchor:
pip install "qed-proof[anchor]"
```

Requires Python 3.11+.

## Quickstart

```python
from qed_proof import QedProof, actions

qp = QedProof(api_key="qed_sk_...")  # or set QED_PROOF_API_KEY

claim = qp.submit_claim(
    actions.github_commit_push(target="owner/repo", sha="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", branch="main"),
    agent_id="my-agent",
    client_claim_id="deploy-42",  # optional: resubmitting the same id returns the same claim (created=False)
)

result = qp.wait_for_verdict(claim.claim_id, timeout=120)
print(result.verdict)  # "verified", "late", "mismatch", "failed" or "unverifiable"

receipt = qp.get_receipt(result.receipt_id)  # no API key needed — receipts are public
```

## List claims

```python
page = qp.list_claims(limit=50, agent_id="my-agent")  # newest first
for claim in page.claims:
    print(claim.claim_id, claim.state, claim.verdict)
page.next_cursor  # str, or None if this was the last page

# or walk every matching claim, following next_cursor automatically:
for claim in qp.iter_claims(agent_id="my-agent", action="github.commit.push"):
    print(claim.claim_id, claim.verdict)
```

`limit` (1-200, default 50), `cursor`, `agent_id`, `action`, `verdict` and `state` are all optional
filters; `list_claims` raises `ValueError` locally if `limit` is out of range, before making a
request. `iter_claims` takes the same filters plus `page_size` (default 50).

## Verify a receipt

A receipt is meant to be checked by anyone, offline, without trusting QED Proof at request time —
only its published Ed25519 keys.

```python
from qed_proof import verify_receipt

keys = qp.get_keys()  # GET /.well-known/poaw-keys.json — no API key needed
report = verify_receipt(receipt, keys)

report.valid                  # bool — every applicable check passed
report.verdict                # the verdict, or None if invalid
report.achieved_trust_level   # 0, 1 or 2 (2 needs inclusion + an on-chain anchor check)
report.checks                 # dict: spec_version, schema, integers_only, key, signature,
                               #       claim_digest, inclusion, anchor — each True/False or a string
                               #       reason ("absent", "not_checked_offline", or a failure code)
report.to_dict()               # the same shape as the reference tool's JSON report
```

Or in one call, using the client's own key fetch:

```python
report = qp.verify(receipt)
```

### Checking the on-chain anchor

Some receipts include a Merkle inclusion proof anchored to an EAS attestation on Base. Checking that
against the chain needs the `anchor` extra and a JSON-RPC URL:

```python
report = verify_receipt(receipt, keys, rpc_url="https://sepolia.base.org")
```

Without `rpc_url`, an anchored receipt's `checks["anchor"]` reads `"not_checked_offline"` rather than
`True` — it's neither proven nor disproven. Any RPC error, decode error or mismatch fails the check
(`checks["anchor"]` becomes a reason string, e.g. `"root_mismatch"`) — it is never treated as a pass.
Calling `verify_receipt(..., rpc_url=...)` without the `anchor` extra installed raises a clear
`ImportError` telling you to `pip install "qed-proof[anchor]"`.

### Anchors at a different tree size, and signed tree heads

An anchor often attests a larger tree than the receipt's own proof. `verify_receipt` then needs an RFC 6962
**consistency proof** to connect the two roots: pass one you already hold, or the issuer's base URL to fetch it.
`qp.verify(...)` uses the client's `base_url` automatically.

```python
report = verify_receipt(receipt, keys, rpc_url="https://sepolia.base.org",
                        consistency=qp.log_consistency(7, 9).raw)   # or issuer="https://api.qedproof.site"
report.checks["anchor"]  # True, "consistency_proof_required" (none obtainable) or "consistency_proof_invalid"
```

A signed tree head (SPEC §8.5) pins the issuer to a single history. Verify it, and optionally check a receipt against it:

```python
from qed_proof import verify_tree_head, verify_consistency

head = qp.log_head()                                  # no API key needed
verify_tree_head(head, keys).valid                    # signature + key check, under its own signing domain
verify_receipt(receipt, keys, head=head.raw)          # adds checks["head"]: the receipt's tree is a prefix of the head
verify_consistency(3, 7, old_root, new_root, proof)   # RFC 9162 §2.1.4.2; roots/nodes as base64url or bytes
```

## The public log

The issuer's Merkle log is free to read, with no authentication (the client never sends your API key for these):

```python
qp.log_head()                            # signed tree head + latest landed anchor
qp.log_consistency(first, second)        # proof that the size-`first` tree is a prefix of size `second`
qp.log_proof(leaf_index, tree_size=None) # inclusion proof for one leaf
qp.log_anchors(limit=20, before=None)    # on-chain anchors, newest first; page with `.next`
qp.log_entries(start=None, limit=50)     # ledger of (leaf_index, leaf_hash, created_at); hashes only
```

Each returns a typed, frozen dataclass (`LogHead`, `ConsistencyProof`, `InclusionProof`, `AnchorPage`, `EntryPage`) with
the original JSON on `.raw`. `AsyncQedProof` has the same methods as coroutines. Treat what the log returns as a claim to
check, not a fact: verify heads and proofs against roots you trust.

## Self-hosted / a different node

Point the client at your own deployment instead of the default `https://api.qedproof.site`:

```python
qp = QedProof(api_key="...", base_url="https://poaw.internal.example.com")
```

## Actions

Typed helpers build the `(action, target, params)` triple for the live verifier profiles, validating
what's cheap to check locally (a receipt's actual verdict is always decided by the destination, never
by the SDK):

```python
from qed_proof import actions

actions.github_commit_push(target="owner/repo", sha="<40 hex>", branch="main")
actions.github_pr_open(target="owner/repo", number=42, base="main", head_sha="<40 hex>")
actions.github_checks_pass(target="owner/repo", sha="<40 hex>")
actions.x_post_publish(target="@handle", post_id="1234567890", text_sha256="<64 hex>")
actions.slack_message_post(target="slack://T0123456789/C0123456789", ts="1234567890.123456")
actions.http_url_status(target="https://example.com", status=200, content_fingerprint="sha256:...")
```

Pass the result straight to `submit_claim`, or pass `action` (a string) with `target=` / `params=`
directly for an action this SDK doesn't yet have a helper for.

## Async

`AsyncQedProof` mirrors the same surface over `httpx.AsyncClient`:

```python
from qed_proof import AsyncQedProof

async with AsyncQedProof(api_key="...") as qp:
    claim = await qp.submit_claim(..., agent_id="my-agent")
    result = await qp.wait_for_verdict(claim.claim_id)
    page = await qp.list_claims(agent_id="my-agent")
    async for claim in qp.iter_claims(agent_id="my-agent"):
        print(claim.claim_id)
```

## Errors

- `QedProofError(status_code, detail)` — any non-2xx response; `detail` is the API's own message.
  The API key is never included in an exception's message, `repr`, or the client's own `repr`.
- `QedProofRateLimited` — a 429, subclassing `QedProofError`, with `.retry_after` (seconds, from the
  `Retry-After` header, or `None`). `wait_for_verdict` handles this for you: it backs off by
  `retry_after` and keeps polling rather than raising.
- `QedProofTimeout` — `wait_for_verdict` didn't see a decided claim within `timeout` seconds.

## Links

- Docs: <https://docs.qedproof.site>
- License: Apache-2.0 (see `LICENSE`)
