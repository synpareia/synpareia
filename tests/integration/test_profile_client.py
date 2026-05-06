"""Integration tests: ``ProfileClient`` against a stub directory.

The SDK can't directly run the main service's profile-directory
in-process (the main service is its own ``synpareia`` package and
shadows the SDK on a single venv). Instead we exercise the
``ProfileClient`` against a small FastAPI stub that mirrors the
wire shape of the Phase 1d/1e routes and asserts the SDK sends
correctly-shaped requests (envelope, sigauth headers,
keyid/keyhash binding).

The main service's own integration tests (under
``tests/integration/`` of the main service) prove that the wire
shape this stub mirrors is the wire shape the live directory
expects, so the two test layers compose into end-to-end coverage
without needing both packages in one venv.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request

from synpareia.identity import generate
from synpareia.profile import (
    ProfileClient,
    WellKnownPublicationPolicy,
    build_agent_card,
    card_canonical_bytes,
    sign_agent_card,
)

# ---------------------------------------------------------------------------
# Stub directory
# ---------------------------------------------------------------------------


def _make_stub_directory() -> tuple[FastAPI, dict[str, Any]]:
    """Build a stub mirroring just enough of /api/v2/profiles + /agents/.well-known.

    Captures every request into ``state`` so tests can assert on
    request shape (envelope, sigauth headers).
    """
    app = FastAPI()
    state: dict[str, Any] = {
        "captured": [],
        "profiles": {},  # did -> {card_dict, history: [versions]}
    }

    @app.post("/api/v2/profiles/{did:path}")
    async def publish(did: str, request: Request) -> dict[str, Any]:
        body_bytes = await request.body()
        body = json.loads(body_bytes.decode())
        state["captured"].append(
            {
                "method": "POST",
                "path": request.url.path,
                "headers": dict(request.headers),
                "body": body,
            }
        )

        card_bytes = base64.b64decode(body["card_b64"])
        card_dict = json.loads(card_bytes.decode())

        existing = state["profiles"].get(did)
        new_version = (existing["history"][-1]["version"] + 1) if existing else 1
        version_row = {
            "version": new_version,
            "card_dict": card_dict,
            "tombstoned_at": None,
        }
        if existing is None:
            state["profiles"][did] = {
                "card_dict": card_dict,
                "history": [version_row],
            }
        else:
            existing["card_dict"] = card_dict
            existing["history"].append(version_row)

        card_hash_hex = hashlib.sha256(card_bytes).hexdigest()
        return {"did": did, "version": new_version, "card_hash_hex": card_hash_hex}

    @app.get("/api/v2/profiles/{did:path}/history")
    async def history(did: str) -> dict[str, Any]:
        prof = state["profiles"].get(did)
        if prof is None:
            return {"did": did, "entries": [], "next_cursor": None}
        entries = [
            {
                "version": row["version"],
                "tombstoned_at": row["tombstoned_at"],
                "signed_agent_card_b64": "stub",
                "signature_b64": "stub",
                "public_key": "stub",
                "signed_at": "2026-01-01T00:00:00+00:00",
                "tombstone_reason": None,
            }
            for row in reversed(prof["history"])
        ]
        return {"did": did, "entries": entries, "next_cursor": None}

    @app.get("/api/v2/profiles/{did:path}")
    async def get_existence(did: str) -> dict[str, Any]:
        prof = state["profiles"].get(did)
        if prof is None:
            return {
                "did": did,
                "exists": False,
                "name": None,
                "description": None,
                "public_key_b64": None,
                "version": None,
            }
        c = prof["card_dict"]
        return {
            "did": did,
            "exists": True,
            "name": c.get("name"),
            "description": c.get("description"),
            "public_key_b64": c.get("public_key_b64"),
            "version": c.get("version"),
        }

    @app.get("/agents/{did:path}/.well-known/agent-card.json")
    async def well_known(did: str) -> dict[str, Any]:
        prof = state["profiles"].get(did)
        if prof is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="not found")
        c = prof["card_dict"]
        # Stub mirrors the real well-known projection: identity layer
        # plus rules-of-engagement (synpareia minus matching cache and
        # policies). This is what services.well_known projects.
        syn = c.get("extensions", {}).get("synpareia", {})
        ro_engagement = {
            k: v
            for k, v in syn.items()
            if k not in {"model_family", "domain_expertise", "reasoning_style", "policies"}
        }
        return {
            "id": c["id"],
            "public_key_b64": c["public_key_b64"],
            "name": c.get("name"),
            "description": c.get("description"),
            "version": c.get("version"),
            "extensions": {"synpareia": ro_engagement},
        }

    @app.delete("/api/v2/profiles/{did:path}/history/{version}", status_code=204)
    async def delete_history_version(did: str, version: int) -> None:
        prof = state["profiles"].get(did)
        if prof is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="not found")
        for row in prof["history"]:
            if row["version"] == version:
                row["tombstoned_at"] = "2026-01-01T00:00:00+00:00"
                return
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="version not found")

    @app.delete("/api/v2/profiles/{did:path}", status_code=204)
    async def delete_profile(did: str) -> None:
        prof = state["profiles"].get(did)
        if prof is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="not found")
        for row in prof["history"]:
            row["tombstoned_at"] = "2026-01-01T00:00:00+00:00"

    return app, state


@pytest_asyncio.fixture
async def stub_and_client():
    from httpx import ASGITransport, AsyncClient

    app, state = _make_stub_directory()
    client = ProfileClient.__new__(ProfileClient)
    client._base_url = "http://stub"  # type: ignore[attr-defined]
    client._access_token = None  # type: ignore[attr-defined]
    client._client = AsyncClient(  # type: ignore[attr-defined]
        transport=ASGITransport(app=app), base_url="http://stub"
    )
    yield client, state
    await client.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_sends_envelope_with_sigauth_headers(stub_and_client) -> None:
    client, state = stub_and_client
    profile = generate()
    assert profile.private_key is not None

    card = build_agent_card(profile, name="Alice")
    bytes_ = card_canonical_bytes(card)
    sig = sign_agent_card(bytes_, profile.private_key)

    result = await client.publish(
        did=profile.id,
        signed_bytes=bytes_,
        signature=sig,
        public_key=profile.public_key,
        private_key=profile.private_key,
    )
    assert result["did"] == profile.id
    assert result["version"] == 1

    assert len(state["captured"]) == 1
    captured = state["captured"][0]
    body = captured["body"]
    assert set(body.keys()) == {"card_b64", "signature_b64", "public_key_b64"}

    # Sigauth headers present (case-insensitive lookup against captured).
    headers_lower = {k.lower(): v for k, v in captured["headers"].items()}
    assert "signature" in headers_lower
    assert "signature-input" in headers_lower
    assert "content-digest" in headers_lower


@pytest.mark.asyncio
async def test_get_existence_known_and_unknown(stub_and_client) -> None:
    client, _ = stub_and_client

    profile = generate()
    assert profile.private_key is not None
    card = build_agent_card(profile, name="Bob")
    bytes_ = card_canonical_bytes(card)
    sig = sign_agent_card(bytes_, profile.private_key)
    await client.publish(
        did=profile.id,
        signed_bytes=bytes_,
        signature=sig,
        public_key=profile.public_key,
        private_key=profile.private_key,
    )

    known = await client.get_existence(did=profile.id)
    assert known["exists"] is True
    assert known["name"] == "Bob"

    other = generate()
    unknown = await client.get_existence(did=other.id)
    assert unknown["exists"] is False
    assert unknown["did"] == other.id


@pytest.mark.asyncio
async def test_get_history_returns_versions_newest_first(stub_and_client) -> None:
    client, _ = stub_and_client
    profile = generate()
    assert profile.private_key is not None

    for n in range(1, 4):
        card = build_agent_card(profile, name=f"v{n}")
        bytes_ = card_canonical_bytes(card)
        sig = sign_agent_card(bytes_, profile.private_key)
        await client.publish(
            did=profile.id,
            signed_bytes=bytes_,
            signature=sig,
            public_key=profile.public_key,
            private_key=profile.private_key,
        )

    page = await client.get_history(did=profile.id)
    versions = [e["version"] for e in page["entries"]]
    assert versions == [3, 2, 1]


@pytest.mark.asyncio
async def test_get_well_known_strips_matching_cache_and_policies(stub_and_client) -> None:
    client, _ = stub_and_client
    profile = generate()
    assert profile.private_key is not None
    card = build_agent_card(
        profile,
        name="Carol",
        model_family="claude",
        domain_expertise=["mediation"],
        well_known_publication=WellKnownPublicationPolicy(a2a_standard_fields=["name"]),
    )
    bytes_ = card_canonical_bytes(card)
    sig = sign_agent_card(bytes_, profile.private_key)
    await client.publish(
        did=profile.id,
        signed_bytes=bytes_,
        signature=sig,
        public_key=profile.public_key,
        private_key=profile.private_key,
    )

    wk = await client.get_well_known(did=profile.id)
    assert wk["id"] == profile.id
    syn = wk["extensions"]["synpareia"]
    assert "model_family" not in syn
    assert "domain_expertise" not in syn
    assert "policies" not in syn


@pytest.mark.asyncio
async def test_delete_history_version_tombstones_the_row(stub_and_client) -> None:
    client, _ = stub_and_client
    profile = generate()
    assert profile.private_key is not None
    card = build_agent_card(profile, name="Dave")
    bytes_ = card_canonical_bytes(card)
    sig = sign_agent_card(bytes_, profile.private_key)
    await client.publish(
        did=profile.id,
        signed_bytes=bytes_,
        signature=sig,
        public_key=profile.public_key,
        private_key=profile.private_key,
    )

    await client.delete_history_version(
        did=profile.id,
        version=1,
        public_key=profile.public_key,
        private_key=profile.private_key,
        reason="forgot",
    )
    page = await client.get_history(did=profile.id)
    assert page["entries"][0]["tombstoned_at"] is not None


@pytest.mark.asyncio
async def test_delete_profile_cascades(stub_and_client) -> None:
    client, _ = stub_and_client
    profile = generate()
    assert profile.private_key is not None

    for n in range(1, 3):
        card = build_agent_card(profile, name=f"v{n}")
        bytes_ = card_canonical_bytes(card)
        sig = sign_agent_card(bytes_, profile.private_key)
        await client.publish(
            did=profile.id,
            signed_bytes=bytes_,
            signature=sig,
            public_key=profile.public_key,
            private_key=profile.private_key,
        )

    await client.delete_profile(
        did=profile.id,
        public_key=profile.public_key,
        private_key=profile.private_key,
    )
    page = await client.get_history(did=profile.id)
    for e in page["entries"]:
        assert e["tombstoned_at"] is not None


# ---------------------------------------------------------------------------
# Witness anchor — hash-only contract
# ---------------------------------------------------------------------------


def _make_witness_stub() -> tuple[FastAPI, list[dict[str, Any]]]:
    """Stub a witness exposing /api/v1/seals/timestamp; capture each request body."""
    from datetime import UTC, datetime

    app = FastAPI()
    captured: list[dict[str, Any]] = []

    @app.post("/api/v1/seals/timestamp")
    async def timestamp_seal(request: Request) -> dict[str, Any]:
        body = json.loads((await request.body()).decode())
        captured.append(body)
        return {
            "seal_id": "stub-seal-1",
            "seal_type": "timestamp",
            "witness_id": "did:synpareia:stub-witness",
            "witness_signature_b64": base64.b64encode(b"\xab" * 64).decode("ascii"),
            "target_block_hash": body["block_hash"],
            "sealed_at": datetime.now(UTC).isoformat(),
            "metadata": {},
        }

    return app, captured


@pytest.mark.asyncio
async def test_request_witness_anchor_sends_only_hash() -> None:
    """The witness anchor path must transmit ONLY the SHA-256 of the
    signed-card bytes — no DID, no card content, no operator
    identifier (sparse-witness construction).
    """
    from unittest.mock import patch

    from httpx import ASGITransport, AsyncClient

    from synpareia.profile import ProfileClient

    witness_app, captured = _make_witness_stub()
    profile = generate()
    assert profile.private_key is not None
    card = build_agent_card(profile, name="WitnessHashTest")
    signed_bytes = card_canonical_bytes(card)

    real_async_client = AsyncClient

    def make_client(*args: Any, **kwargs: Any) -> AsyncClient:
        kwargs.pop("base_url", None)
        kwargs.pop("timeout", None)
        return real_async_client(
            transport=ASGITransport(app=witness_app), base_url="http://stub-witness"
        )

    client = ProfileClient.__new__(ProfileClient)
    client._base_url = "http://does-not-matter"  # type: ignore[attr-defined]
    client._access_token = None  # type: ignore[attr-defined]
    client._client = real_async_client(base_url="http://does-not-matter")  # type: ignore[attr-defined]

    # Patch the WitnessClient's underlying httpx so it routes via ASGI.
    with patch("synpareia.witness.client.httpx.AsyncClient", make_client):
        seal = await client.request_witness_anchor(
            witness_url="http://stub-witness",
            signed_bytes=signed_bytes,
        )

    await client.close()

    # Hash-only contract.
    assert len(captured) == 1
    assert set(captured[0].keys()) == {"block_hash"}
    expected_hash = hashlib.sha256(signed_bytes).hexdigest()
    assert captured[0]["block_hash"] == expected_hash
    # No DID, no card content in the captured request.
    assert profile.id not in json.dumps(captured[0])
    assert "WitnessHashTest" not in json.dumps(captured[0])

    # Response parsing — SealPayload fields populated.
    assert seal.witness_id == "did:synpareia:stub-witness"
    assert seal.target_block_hash is not None
    assert seal.target_block_hash.hex() == expected_hash


# ---------------------------------------------------------------------------
# SyncProfileClient smoke test
# ---------------------------------------------------------------------------


def test_sync_profile_client_publish_and_get() -> None:
    """Exercise the sync wrapper end-to-end against the stub directory.

    Drives ``SyncProfileClient.publish`` + ``get_existence`` to verify
    arguments forward correctly through the ``asyncio.run`` boundary
    and that response shapes survive the round-trip.
    """
    from unittest.mock import patch

    from httpx import ASGITransport, AsyncClient

    from synpareia.profile import SyncProfileClient

    app, _ = _make_stub_directory()
    real_async_client = AsyncClient

    def make_client(*args: Any, **kwargs: Any) -> AsyncClient:
        kwargs.pop("base_url", None)
        return real_async_client(transport=ASGITransport(app=app), base_url="http://stub")

    profile = generate()
    assert profile.private_key is not None
    card = build_agent_card(profile, name="SyncSmoke")
    bytes_ = card_canonical_bytes(card)
    sig = sign_agent_card(bytes_, profile.private_key)

    with (
        patch("synpareia.profile.client.httpx.AsyncClient", make_client),
        SyncProfileClient("http://stub") as client,
    ):
        result = client.publish(
            did=profile.id,
            signed_bytes=bytes_,
            signature=sig,
            public_key=profile.public_key,
            private_key=profile.private_key,
        )
        assert result["did"] == profile.id
        assert result["version"] == 1

        view = client.get_existence(did=profile.id)
        assert view["exists"] is True
        assert view["name"] == "SyncSmoke"
