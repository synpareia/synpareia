"""HTTP client for the Phase 1d/1e profile-directory routes.

Async ``ProfileClient`` and sync ``SyncProfileClient`` mirror the
``WitnessClient`` pattern in ``synpareia.witness.client``. The
network surface is gated on the ``synpareia[profile]`` extra
(httpx); the local-only ``card.py`` helpers don't need it.

**Sigauth.** Every authenticated route signs the request with RFC
9421 via ``synpareia.auth.rfc9421.sign_request``. The signature's
``keyid`` is the DID being acted on.

**Witness anchor.** The ``request_witness_anchor`` helper requests
``/api/v1/seals/timestamp`` against the witness — the SHA-256 of
the signed-card bytes is the only data sent. Returns the parsed
``SealPayload``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

import httpx

from synpareia.auth.rfc9421 import sign_request
from synpareia.identity import _derive_did
from synpareia.types import DID_PREFIX

if TYPE_CHECKING:
    from synpareia.seal import SealPayload

__all__ = ["ProfileClient", "SyncProfileClient"]


# Canonical synpareia DID shape, pinned at the wrapper boundary (PT-002
# defence-in-depth) so a caller can't slip a path-traversal segment
# past the f-string interpolation in client method paths. The
# server-side validator is the real gate; this is the SDK refusing to
# dispatch a request the server is going to reject anyway.
#
# DID_PREFIX from synpareia.types is the single source of truth for
# the literal prefix; the trailing hex window is sha256-shaped (64
# lowercase hex chars, matching identity._derive_did's
# hashlib.sha256(pk).hexdigest() output).
_DID_RE = re.compile(rf"^{re.escape(DID_PREFIX)}[0-9a-f]{{64}}$")


def _validate_did(did: str) -> None:
    if not _DID_RE.fullmatch(did):
        msg = f"did is not a canonical synpareia DID: {did!r}"
        raise ValueError(msg)


class ProfileClient:
    """Async HTTP client for the synpareia profile directory.

    Usage::

        async with ProfileClient("https://synpareia.example") as client:
            await client.publish(
                did=profile.id,
                signed_bytes=signed_bytes,
                signature=signature,
                public_key=profile.public_key,
                private_key=profile.private_key,
            )
            view = await client.get_existence(did=profile.id)
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        access_token: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._access_token = access_token
        headers = {"X-Access-Token": access_token} if access_token else None
        self._client = httpx.AsyncClient(base_url=self._base_url, timeout=timeout, headers=headers)

    async def __aenter__(self) -> ProfileClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    # -----------------------------------------------------------------
    # POST /api/v2/profiles/{did} — publish/update
    # -----------------------------------------------------------------

    async def publish(
        self,
        *,
        did: str,
        signed_bytes: bytes,
        signature: bytes,
        public_key: bytes,
        private_key: bytes,
    ) -> dict[str, Any]:
        """Publish or update an agent card.

        ``signed_bytes`` are the canonical card bytes from
        ``card_canonical_bytes(card)``; ``signature`` is the result
        of ``sign_agent_card(signed_bytes, private_key)``;
        ``public_key`` and ``private_key`` are the operator's raw
        Ed25519 keys (``private_key`` is needed for the RFC 9421
        request signature).

        Returns the directory's response body
        (``{did, version, card_hash_hex}``). Raises
        ``httpx.HTTPStatusError`` on non-2xx responses; the body's
        structured ``{detail, code}`` is preserved on ``.response``.

        Raises ``ValueError`` (PT-001 / PT-002 defence-in-depth) if
        ``did`` is not canonical, if ``did`` doesn't match
        ``"did:synpareia:" + sha256(public_key).hex()``, or if the
        embedded ``id`` field in ``signed_bytes`` (when parseable)
        disagrees with ``did``. The server-side validator is the
        real gate; these checks fail-fast at the SDK layer so the
        caller doesn't ship a request that's guaranteed to be
        rejected.
        """
        _validate_did(did)
        if did != _derive_did(public_key):
            msg = (
                "did argument does not match public_key derivation "
                "(did = 'did:synpareia:' + sha256(public_key).hex())"
            )
            raise ValueError(msg)
        try:
            embedded = json.loads(signed_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            embedded = None
        if isinstance(embedded, dict) and "id" in embedded and embedded["id"] != did:
            msg = (
                f"signed_bytes embedded id {embedded['id']!r} disagrees with did argument {did!r}"
            )
            raise ValueError(msg)
        path = f"/api/v2/profiles/{did}"
        body = json.dumps(
            {
                "card_b64": base64.b64encode(signed_bytes).decode("ascii"),
                "signature_b64": base64.b64encode(signature).decode("ascii"),
                "public_key_b64": base64.b64encode(public_key).decode("ascii"),
            }
        ).encode("utf-8")
        headers = self._sigauth_headers(
            method="POST",
            path=path,
            body=body,
            private_key=private_key,
            keyid=did,
        )
        headers["Content-Type"] = "application/json"
        resp = await self._client.post(path, content=body, headers=headers)
        resp.raise_for_status()
        return _ensure_dict(resp.json())

    # -----------------------------------------------------------------
    # GET /api/v2/profiles/{did} — existence layer
    # -----------------------------------------------------------------

    async def get_existence(self, *, did: str) -> dict[str, Any]:
        """Fetch the existence-layer view for ``did``.

        Returns ``{did, exists, name, description, public_key_b64,
        version}``. Unknown DIDs return ``exists=False`` with the
        same envelope (enumeration-defence).

        Raises ``ValueError`` if ``did`` is not a canonical
        ``did:synpareia:<64hex>`` (PT-002 defence-in-depth).
        """
        _validate_did(did)
        resp = await self._client.get(f"/api/v2/profiles/{did}")
        resp.raise_for_status()
        return _ensure_dict(resp.json())

    # -----------------------------------------------------------------
    # GET /api/v2/profiles/{did}/history — paginated history
    # -----------------------------------------------------------------

    async def get_history(
        self,
        *,
        did: str,
        limit: int = 50,
        cursor: int | None = None,
    ) -> dict[str, Any]:
        """Fetch paginated card-version history (newest-first).

        Raises ``ValueError`` if ``did`` is not canonical
        (PT-002 defence-in-depth).
        """
        _validate_did(did)
        params: dict[str, Any] = {"limit": limit}
        if cursor is not None:
            params["cursor"] = cursor
        resp = await self._client.get(f"/api/v2/profiles/{did}/history", params=params)
        resp.raise_for_status()
        return _ensure_dict(resp.json())

    # -----------------------------------------------------------------
    # GET /agents/{did}/.well-known/agent-card.json
    # -----------------------------------------------------------------

    async def get_well_known(self, *, did: str) -> dict[str, Any]:
        """Fetch the A2A discovery surface for ``did``.

        Subject to the operator's
        ``policies.well_known_publication.a2a_standard_fields``;
        synpareia identity layer + rules-of-engagement always
        present. Unknown DIDs return 404.

        Raises ``ValueError`` if ``did`` is not canonical
        (PT-002 defence-in-depth).
        """
        _validate_did(did)
        resp = await self._client.get(f"/agents/{did}/.well-known/agent-card.json")
        resp.raise_for_status()
        return _ensure_dict(resp.json())

    # -----------------------------------------------------------------
    # DELETE /api/v2/profiles/{did}/history/{version}
    # -----------------------------------------------------------------

    async def delete_history_version(
        self,
        *,
        did: str,
        version: int,
        public_key: bytes,
        private_key: bytes,
        reason: str | None = None,
    ) -> None:
        """Tombstone a single history version. Operator-authenticated.

        Returns None on success; raises ``httpx.HTTPStatusError``
        with the structured 403 body when persistence opt-in
        blocks the call (``code == "persistence_opt_in"``).

        Raises ``ValueError`` if ``did`` is not canonical
        (PT-002 defence-in-depth).
        """
        _validate_did(did)
        path = f"/api/v2/profiles/{did}/history/{version}"
        body = json.dumps(
            {
                "reason": reason,
                "requester_public_key_b64": base64.b64encode(public_key).decode("ascii"),
            }
        ).encode("utf-8")
        headers = self._sigauth_headers(
            method="DELETE",
            path=path,
            body=body,
            private_key=private_key,
            keyid=did,
        )
        headers["Content-Type"] = "application/json"
        resp = await self._client.request("DELETE", path, content=body, headers=headers)
        resp.raise_for_status()

    # -----------------------------------------------------------------
    # DELETE /api/v2/profiles/{did}
    # -----------------------------------------------------------------

    async def delete_profile(
        self,
        *,
        did: str,
        public_key: bytes,
        private_key: bytes,
        reason: str | None = None,
    ) -> None:
        """Tombstone every history version (full profile delete).

        Same persistence-opt-in semantics as
        ``delete_history_version`` — ``card_history`` or
        ``key_chain`` opt-in returns 403.

        Raises ``ValueError`` if ``did`` is not canonical
        (PT-002 defence-in-depth).
        """
        _validate_did(did)
        path = f"/api/v2/profiles/{did}"
        body = json.dumps(
            {
                "reason": reason,
                "requester_public_key_b64": base64.b64encode(public_key).decode("ascii"),
            }
        ).encode("utf-8")
        headers = self._sigauth_headers(
            method="DELETE",
            path=path,
            body=body,
            private_key=private_key,
            keyid=did,
        )
        headers["Content-Type"] = "application/json"
        resp = await self._client.request("DELETE", path, content=body, headers=headers)
        resp.raise_for_status()

    # -----------------------------------------------------------------
    # Witness anchor — hash-only timestamp seal
    # -----------------------------------------------------------------

    async def request_witness_anchor(
        self,
        *,
        witness_url: str,
        signed_bytes: bytes,
        access_token: str | None = None,
    ) -> SealPayload:
        """Request a hash-only timestamp seal from ``witness_url``.

        The witness sees only ``SHA-256(signed_bytes)`` — never the
        DID, the card content, or any operator identifier
        (sparse-witness construction). Returns the parsed
        ``SealPayload`` from ``synpareia.witness.client``.

        Lives on ``ProfileClient`` rather than ``WitnessClient``
        because the operator typically holds one ``ProfileClient``
        per directory; the witness URL is per-call so the same
        client can anchor against any witness on demand.
        """
        from synpareia.witness.client import WitnessClient

        card_hash = hashlib.sha256(signed_bytes).digest()
        async with WitnessClient(witness_url) as witness:
            if access_token:
                witness._client.headers["X-Access-Token"] = access_token  # noqa: SLF001
            return await witness.timestamp_seal(card_hash)

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _sigauth_headers(
        self,
        *,
        method: str,
        path: str,
        body: bytes,
        private_key: bytes,
        keyid: str,
    ) -> dict[str, str]:
        target_uri = f"{self._base_url}{path}"
        signed = sign_request(
            method=method,
            target_uri=target_uri,
            body=body,
            private_key=private_key,
            keyid=keyid,
            nonce=hashlib.sha256(body + path.encode() + method.encode()).hexdigest()[:16],
        )
        return signed.headers()


# ---------------------------------------------------------------------------
# Sync wrapper
# ---------------------------------------------------------------------------


class SyncProfileClient:
    """Synchronous wrapper around :class:`ProfileClient`.

    Each call runs the underlying coroutine via ``asyncio.run``.
    Use the async client directly when you already have an event
    loop; this wrapper is for scripts and one-shot CLI tools.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        access_token: str | None = None,
    ) -> None:
        self._async_client = ProfileClient(base_url, timeout=timeout, access_token=access_token)

    def __enter__(self) -> SyncProfileClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        asyncio.run(self._async_client.close())

    def publish(
        self,
        *,
        did: str,
        signed_bytes: bytes,
        signature: bytes,
        public_key: bytes,
        private_key: bytes,
    ) -> dict[str, Any]:
        return asyncio.run(
            self._async_client.publish(
                did=did,
                signed_bytes=signed_bytes,
                signature=signature,
                public_key=public_key,
                private_key=private_key,
            )
        )

    def get_existence(self, *, did: str) -> dict[str, Any]:
        return asyncio.run(self._async_client.get_existence(did=did))

    def get_history(
        self, *, did: str, limit: int = 50, cursor: int | None = None
    ) -> dict[str, Any]:
        return asyncio.run(self._async_client.get_history(did=did, limit=limit, cursor=cursor))

    def get_well_known(self, *, did: str) -> dict[str, Any]:
        return asyncio.run(self._async_client.get_well_known(did=did))

    def delete_history_version(
        self,
        *,
        did: str,
        version: int,
        public_key: bytes,
        private_key: bytes,
        reason: str | None = None,
    ) -> None:
        asyncio.run(
            self._async_client.delete_history_version(
                did=did,
                version=version,
                public_key=public_key,
                private_key=private_key,
                reason=reason,
            )
        )

    def delete_profile(
        self,
        *,
        did: str,
        public_key: bytes,
        private_key: bytes,
        reason: str | None = None,
    ) -> None:
        asyncio.run(
            self._async_client.delete_profile(
                did=did,
                public_key=public_key,
                private_key=private_key,
                reason=reason,
            )
        )

    def request_witness_anchor(
        self,
        *,
        witness_url: str,
        signed_bytes: bytes,
        access_token: str | None = None,
    ) -> SealPayload:
        return asyncio.run(
            self._async_client.request_witness_anchor(
                witness_url=witness_url,
                signed_bytes=signed_bytes,
                access_token=access_token,
            )
        )


def _ensure_dict(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        msg = f"expected JSON object response, got {type(payload).__name__}"
        raise TypeError(msg)
    return payload
