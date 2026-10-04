"""HTTP client for QED Proof: submit claims, poll for a verdict, fetch a receipt and the public keys.

Endpoint shapes follow ``oss/node/src/poaw_node/app.py`` (``ClaimIn`` in ``models.py``, and
``Store.claim_status`` / ``Store.receipt_with_proof`` in ``store.py``).
"""
from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from .actions import Action
from .log import (
    AnchorPage, ConsistencyProof, EntryPage, InclusionProof, LogHead, _params,
)
from .verify import VerifyReport, verify_receipt

__all__ = [
    "QedProof", "AsyncQedProof", "ClaimResult", "ClaimPage",
    "QedProofError", "QedProofRateLimited", "QedProofTimeout",
]

DEFAULT_BASE_URL = "https://api.qedproof.site"
DEFAULT_TIMEOUT = 30
_ENV_KEY = "QED_PROOF_API_KEY"
LIST_CLAIMS_DEFAULT_LIMIT = 50
LIST_CLAIMS_MIN_LIMIT = 1
LIST_CLAIMS_MAX_LIMIT = 200


class QedProofError(Exception):
    """An error response from the QED Proof API (a FastAPI ``{"detail": ...}`` body).

    The API key is never included in this exception's message, repr or args — only the status code
    and the server's own detail text.
    """

    def __init__(self, status_code: int, detail: Any):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"QED Proof API error {status_code}: {detail!r}")


class QedProofRateLimited(QedProofError):
    """A 429 response. ``retry_after`` is the ``Retry-After`` header in whole seconds, if present."""

    def __init__(self, status_code: int, detail: Any, retry_after: int | None):
        self.retry_after = retry_after
        super().__init__(status_code, detail)


class QedProofTimeout(Exception):
    """``wait_for_verdict`` did not observe a decided claim within ``timeout`` seconds."""

    def __init__(self, claim_id: str, timeout: float):
        self.claim_id = claim_id
        self.timeout = timeout
        super().__init__(f"claim {claim_id} was not decided within {timeout}s")


@dataclass(frozen=True)
class ClaimResult:
    """A claim as the API reports it (``Store.claim_status`` / the ``POST /v1/claims`` response)."""

    claim_id: str
    state: str  # "queued" | "decided"
    attempts: int
    receipt_id: str | None
    verdict: str | None
    created: bool | None = None  # only set on the response to submit_claim
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def decided(self) -> bool:
        return self.state == "decided"

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> "ClaimResult":
        return cls(
            claim_id=d["claim_id"], state=d["state"], attempts=d.get("attempts", 0),
            receipt_id=d.get("receipt_id"), verdict=d.get("verdict"), created=d.get("created"), raw=d,
        )


@dataclass(frozen=True)
class ClaimPage:
    """One page of ``GET /v1/claims`` (newest first, keyset-paginated)."""

    claims: list[ClaimResult]
    next_cursor: str | None
    raw: dict[str, Any] = field(default_factory=dict)


def _list_claims_params(*, limit: int, cursor: str | None, agent_id: str | None, action: str | None,
                        verdict: str | None, state: str | None) -> dict[str, Any]:
    if not (LIST_CLAIMS_MIN_LIMIT <= limit <= LIST_CLAIMS_MAX_LIMIT):
        raise ValueError(f"limit must be between {LIST_CLAIMS_MIN_LIMIT} and {LIST_CLAIMS_MAX_LIMIT}, got {limit}")
    params: dict[str, Any] = {"limit": limit}
    if cursor is not None:
        params["cursor"] = cursor
    if agent_id is not None:
        params["agent_id"] = agent_id
    if action is not None:
        params["action"] = action
    if verdict is not None:
        params["verdict"] = verdict
    if state is not None:
        params["state"] = state
    return params


def _claim_page_from_dict(d: dict[str, Any]) -> ClaimPage:
    return ClaimPage(claims=[ClaimResult._from_dict(c) for c in d.get("claims", [])],
                     next_cursor=d.get("next_cursor"), raw=d)


def _now_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _claim_body(action: Action | str, *, target: str | None, params: dict[str, Any] | None,
                agent_id: str, client_claim_id: str | None, claimed_at: str | None) -> dict[str, Any]:
    if isinstance(action, Action):
        action_name, resolved_target, resolved_params = action.action, action.target, dict(action.params)
    else:
        action_name, resolved_target, resolved_params = action, target, dict(params or {})
    if resolved_target is None:
        raise ValueError("target is required when action is a plain string")
    return {
        "client_claim_id": client_claim_id or str(uuid.uuid4()),
        "agent_id": agent_id,
        "action": action_name,
        "target": resolved_target,
        "params": resolved_params,
        "claimed_at": claimed_at or _now_iso(),
    }


def _raise_for_status(resp: httpx.Response) -> None:
    if resp.status_code < 400:
        return
    try:
        detail = resp.json().get("detail", resp.text)
    except ValueError:
        detail = resp.text
    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After")
        raise QedProofRateLimited(429, detail, int(retry_after) if retry_after and retry_after.isdigit() else None)
    raise QedProofError(resp.status_code, detail)


class QedProof:
    """Synchronous client. ``api_key`` falls back to the ``QED_PROOF_API_KEY`` environment variable."""

    def __init__(self, api_key: str | None = None, base_url: str = DEFAULT_BASE_URL, timeout: float = DEFAULT_TIMEOUT,
                http_client: httpx.Client | None = None):
        self._api_key = api_key or os.environ.get(_ENV_KEY)
        self._base_url = base_url.rstrip("/")
        self._client = http_client or httpx.Client(timeout=timeout)
        self._owns_client = http_client is None

    def __repr__(self) -> str:  # never leak the key
        return f"QedProof(base_url={self._base_url!r})"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "QedProof":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _auth_headers(self) -> dict[str, str]:
        if not self._api_key:
            raise QedProofError(401, "no API key set (pass api_key= or set QED_PROOF_API_KEY)")
        return {"Authorization": f"Bearer {self._api_key}"}

    def submit_claim(self, action: Action | str, *, target: str | None = None, params: dict[str, Any] | None = None,
                     agent_id: str, client_claim_id: str | None = None, claimed_at: str | None = None) -> ClaimResult:
        body = _claim_body(action, target=target, params=params, agent_id=agent_id,
                           client_claim_id=client_claim_id, claimed_at=claimed_at)
        resp = self._client.post(f"{self._base_url}/v1/claims", json=body, headers=self._auth_headers())
        _raise_for_status(resp)
        return ClaimResult._from_dict(resp.json())

    def get_claim(self, claim_id: str) -> ClaimResult:
        resp = self._client.get(f"{self._base_url}/v1/claims/{quote(claim_id, safe='')}", headers=self._auth_headers())
        _raise_for_status(resp)
        return ClaimResult._from_dict(resp.json())

    def wait_for_verdict(self, claim_id: str, timeout: float = 120, poll_interval: float = 2) -> ClaimResult:
        deadline = time.monotonic() + timeout
        interval = poll_interval
        while True:
            try:
                claim = self.get_claim(claim_id)
            except QedProofRateLimited as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise QedProofTimeout(claim_id, timeout) from exc
                time.sleep(min(exc.retry_after or interval, remaining))
                continue
            if claim.decided:
                return claim
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QedProofTimeout(claim_id, timeout)
            time.sleep(min(interval, remaining))
            interval = min(interval * 2, 30)

    def list_claims(self, *, limit: int = LIST_CLAIMS_DEFAULT_LIMIT, cursor: str | None = None,
                    agent_id: str | None = None, action: str | None = None, verdict: str | None = None,
                    state: str | None = None) -> ClaimPage:
        """``GET /v1/claims``, newest first. Raises :class:`ValueError` locally if ``limit`` is out of range."""
        params = _list_claims_params(limit=limit, cursor=cursor, agent_id=agent_id, action=action,
                                     verdict=verdict, state=state)
        resp = self._client.get(f"{self._base_url}/v1/claims", params=params, headers=self._auth_headers())
        _raise_for_status(resp)
        return _claim_page_from_dict(resp.json())

    def iter_claims(self, *, page_size: int = LIST_CLAIMS_DEFAULT_LIMIT, agent_id: str | None = None,
                    action: str | None = None, verdict: str | None = None, state: str | None = None):
        """Yield every :class:`ClaimResult` matching the filters, following ``next_cursor`` until exhausted."""
        cursor: str | None = None
        while True:
            page = self.list_claims(limit=page_size, cursor=cursor, agent_id=agent_id, action=action,
                                    verdict=verdict, state=state)
            yield from page.claims
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    def get_receipt(self, receipt_id: str) -> dict[str, Any]:
        resp = self._client.get(f"{self._base_url}/v1/receipts/{quote(receipt_id, safe='')}")  # no auth: receipts are public
        _raise_for_status(resp)
        return resp.json()

    def get_keys(self) -> dict[str, Any]:
        resp = self._client.get(f"{self._base_url}/.well-known/poaw-keys.json")
        _raise_for_status(resp)
        return resp.json()

    def verify(self, receipt: dict[str, Any], rpc_url: str | None = None, *, head: Any = None,
               consistency: Any = None) -> VerifyReport:
        """Fetch the issuer's keys and verify ``receipt``. A consistency proof the anchor or ``head`` check needs is
        taken from ``consistency`` if given, else fetched from this client's ``base_url``."""
        keys = self.get_keys()

        def fetch(url: str) -> Any:
            resp = self._client.get(url)
            _raise_for_status(resp)
            return resp.json()

        return verify_receipt(receipt, keys, rpc_url=rpc_url, head=head, consistency=consistency,
                              issuer=self._base_url, fetch=fetch)

    # --- public Merkle log (SPEC §8.6): free, no auth; the API key is never sent -----------------
    def _log_get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self._client.get(f"{self._base_url}/v1/log/{path}", params=params or None)
        _raise_for_status(resp)
        return resp.json()

    def log_head(self) -> LogHead:
        """``GET /v1/log/head``: the signed tree head and the latest landed anchor. Check with ``verify_tree_head``."""
        return LogHead._from_dict(self._log_get("head"))

    def log_consistency(self, first: int, second: int) -> ConsistencyProof:
        """``GET /v1/log/consistency``: RFC 6962 proof that the size-``first`` tree is a prefix of size ``second``."""
        return ConsistencyProof._from_dict(self._log_get("consistency", {"first": first, "second": second}))

    def log_proof(self, leaf_index: int, tree_size: int | None = None) -> InclusionProof:
        """``GET /v1/log/proof``: inclusion proof for a leaf (``tree_size`` defaults to the current size)."""
        return InclusionProof._from_dict(self._log_get("proof", _params(leaf_index=leaf_index, tree_size=tree_size)))

    def log_anchors(self, limit: int = 20, before: int | None = None) -> AnchorPage:
        """``GET /v1/log/anchors``: landed on-chain anchors, newest first (``limit`` <= 100)."""
        return AnchorPage._from_dict(self._log_get("anchors", _params(limit=limit, before=before)))

    def log_entries(self, start: int | None = None, limit: int = 50) -> EntryPage:
        """``GET /v1/log/entries``: ledger rows (``leaf_index``, ``leaf_hash``, ``created_at``), ascending (``limit`` <= 100)."""
        return EntryPage._from_dict(self._log_get("entries", _params(start=start, limit=limit)))


class AsyncQedProof:
    """Asynchronous client with the same surface as :class:`QedProof`, over ``httpx.AsyncClient``."""

    def __init__(self, api_key: str | None = None, base_url: str = DEFAULT_BASE_URL, timeout: float = DEFAULT_TIMEOUT,
                http_client: httpx.AsyncClient | None = None):
        self._api_key = api_key or os.environ.get(_ENV_KEY)
        self._base_url = base_url.rstrip("/")
        self._client = http_client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = http_client is None

    def __repr__(self) -> str:
        return f"AsyncQedProof(base_url={self._base_url!r})"

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "AsyncQedProof":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def _auth_headers(self) -> dict[str, str]:
        if not self._api_key:
            raise QedProofError(401, "no API key set (pass api_key= or set QED_PROOF_API_KEY)")
        return {"Authorization": f"Bearer {self._api_key}"}

    async def submit_claim(self, action: Action | str, *, target: str | None = None, params: dict[str, Any] | None = None,
                          agent_id: str, client_claim_id: str | None = None, claimed_at: str | None = None) -> ClaimResult:
        body = _claim_body(action, target=target, params=params, agent_id=agent_id,
                           client_claim_id=client_claim_id, claimed_at=claimed_at)
        resp = await self._client.post(f"{self._base_url}/v1/claims", json=body, headers=self._auth_headers())
        _raise_for_status(resp)
        return ClaimResult._from_dict(resp.json())

    async def get_claim(self, claim_id: str) -> ClaimResult:
        resp = await self._client.get(f"{self._base_url}/v1/claims/{quote(claim_id, safe='')}", headers=self._auth_headers())
        _raise_for_status(resp)
        return ClaimResult._from_dict(resp.json())

    async def wait_for_verdict(self, claim_id: str, timeout: float = 120, poll_interval: float = 2) -> ClaimResult:
        import asyncio
        deadline = time.monotonic() + timeout
        interval = poll_interval
        while True:
            try:
                claim = await self.get_claim(claim_id)
            except QedProofRateLimited as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise QedProofTimeout(claim_id, timeout) from exc
                await asyncio.sleep(min(exc.retry_after or interval, remaining))
                continue
            if claim.decided:
                return claim
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QedProofTimeout(claim_id, timeout)
            await asyncio.sleep(min(interval, remaining))
            interval = min(interval * 2, 30)

    async def list_claims(self, *, limit: int = LIST_CLAIMS_DEFAULT_LIMIT, cursor: str | None = None,
                          agent_id: str | None = None, action: str | None = None, verdict: str | None = None,
                          state: str | None = None) -> ClaimPage:
        """``GET /v1/claims``, newest first. Raises :class:`ValueError` locally if ``limit`` is out of range."""
        params = _list_claims_params(limit=limit, cursor=cursor, agent_id=agent_id, action=action,
                                     verdict=verdict, state=state)
        resp = await self._client.get(f"{self._base_url}/v1/claims", params=params, headers=self._auth_headers())
        _raise_for_status(resp)
        return _claim_page_from_dict(resp.json())

    async def iter_claims(self, *, page_size: int = LIST_CLAIMS_DEFAULT_LIMIT, agent_id: str | None = None,
                          action: str | None = None, verdict: str | None = None, state: str | None = None):
        """Async-yield every :class:`ClaimResult` matching the filters, following ``next_cursor`` until exhausted."""
        cursor: str | None = None
        while True:
            page = await self.list_claims(limit=page_size, cursor=cursor, agent_id=agent_id, action=action,
                                          verdict=verdict, state=state)
            for c in page.claims:
                yield c
            if page.next_cursor is None:
                return
            cursor = page.next_cursor

    async def get_receipt(self, receipt_id: str) -> dict[str, Any]:
        resp = await self._client.get(f"{self._base_url}/v1/receipts/{quote(receipt_id, safe='')}")
        _raise_for_status(resp)
        return resp.json()

    async def get_keys(self) -> dict[str, Any]:
        resp = await self._client.get(f"{self._base_url}/.well-known/poaw-keys.json")
        _raise_for_status(resp)
        return resp.json()

    async def verify(self, receipt: dict[str, Any], rpc_url: str | None = None, *, head: Any = None,
                     consistency: Any = None) -> VerifyReport:
        """Fetch the issuer's keys and verify ``receipt``. A consistency proof the anchor or ``head`` check needs is
        taken from ``consistency`` if given, else fetched from this client's ``base_url``."""
        import asyncio
        keys = await self.get_keys()
        # verify_receipt is synchronous (it may also call a JSON-RPC endpoint), so run it off the event loop.
        return await asyncio.to_thread(
            verify_receipt, receipt, keys, rpc_url, None,
            head=head, consistency=consistency, issuer=self._base_url,
        )

    # --- public Merkle log (SPEC §8.6): free, no auth; the API key is never sent -----------------
    async def _log_get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = await self._client.get(f"{self._base_url}/v1/log/{path}", params=params or None)
        _raise_for_status(resp)
        return resp.json()

    async def log_head(self) -> LogHead:
        """``GET /v1/log/head``: the signed tree head and the latest landed anchor. Check with ``verify_tree_head``."""
        return LogHead._from_dict(await self._log_get("head"))

    async def log_consistency(self, first: int, second: int) -> ConsistencyProof:
        """``GET /v1/log/consistency``: RFC 6962 proof that the size-``first`` tree is a prefix of size ``second``."""
        return ConsistencyProof._from_dict(await self._log_get("consistency", {"first": first, "second": second}))

    async def log_proof(self, leaf_index: int, tree_size: int | None = None) -> InclusionProof:
        """``GET /v1/log/proof``: inclusion proof for a leaf (``tree_size`` defaults to the current size)."""
        return InclusionProof._from_dict(await self._log_get("proof", _params(leaf_index=leaf_index, tree_size=tree_size)))

    async def log_anchors(self, limit: int = 20, before: int | None = None) -> AnchorPage:
        """``GET /v1/log/anchors``: landed on-chain anchors, newest first (``limit`` <= 100)."""
        return AnchorPage._from_dict(await self._log_get("anchors", _params(limit=limit, before=before)))

    async def log_entries(self, start: int | None = None, limit: int = 50) -> EntryPage:
        """``GET /v1/log/entries``: ledger rows (``leaf_index``, ``leaf_hash``, ``created_at``), ascending (``limit`` <= 100)."""
        return EntryPage._from_dict(await self._log_get("entries", _params(start=start, limit=limit)))
