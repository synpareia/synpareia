"""HTTP client for the synpareia witness service."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from synpareia.seal import SealPayload
from synpareia.types import SealType


@dataclass(frozen=True)
class WitnessInfo:
    """Witness service identity information."""

    witness_id: str
    public_key: bytes
    public_key_b64: str
    public_key_hex: str
    version: str


@dataclass(frozen=True)
class ConclusionStatus:
    """Status of a blind conclusion."""

    conclusion_key: str
    status: str  # "waiting", "ready", "expired"
    party_a_commitment: str | None = None
    party_b_commitment: str | None = None
    party_a_seal_id: str | None = None
    party_b_seal_id: str | None = None


@dataclass(frozen=True)
class ChallengeInfo:
    """Issued liveness challenge."""

    challenge_id: str
    nonce_hex: str
    deadline: datetime
    chain_id: str | None = None


class WitnessClient:
    """Async HTTP client for the synpareia witness service.

    Usage::

        async with WitnessClient("https://witness.synpareia.com") as client:
            info = await client.get_witness_info()
            seal = await client.timestamp_seal(my_profile.id, block.content_hash)
    """

    def __init__(self, base_url: str, *, timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(base_url=self._base_url, timeout=timeout)

    async def __aenter__(self) -> WitnessClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def get_witness_info(self) -> WitnessInfo:
        """Get the witness's public identity."""
        resp = await self._client.get("/api/v1/witness")
        resp.raise_for_status()
        data = resp.json()
        return WitnessInfo(
            witness_id=data["witness_id"],
            public_key=bytes.fromhex(data["public_key_hex"]),
            public_key_b64=data["public_key_b64"],
            public_key_hex=data["public_key_hex"],
            version=data["version"],
        )

    async def timestamp_seal(self, requester_id: str, block_hash: bytes) -> SealPayload:
        """Request a timestamp seal for a block hash."""
        resp = await self._client.post(
            "/api/v1/seals/timestamp",
            json={"requester_id": requester_id, "block_hash": block_hash.hex()},
        )
        resp.raise_for_status()
        return _parse_seal_response(resp.json())

    async def state_seal(self, requester_id: str, chain_id: str, chain_head: bytes) -> SealPayload:
        """Request a state seal for a chain checkpoint."""
        resp = await self._client.post(
            "/api/v1/seals/state",
            json={
                "requester_id": requester_id,
                "chain_id": chain_id,
                "chain_head": chain_head.hex(),
            },
        )
        resp.raise_for_status()
        return _parse_seal_response(resp.json())

    async def get_seal(self, seal_id: str) -> SealPayload:
        """Retrieve a seal by ID."""
        resp = await self._client.get(f"/api/v1/seals/{seal_id}")
        resp.raise_for_status()
        return _parse_seal_response(resp.json())

    async def submit_conclusion(
        self, conclusion_key: str, requester_id: str, commitment_hash: bytes
    ) -> ConclusionStatus:
        """Submit a commitment to a blind conclusion."""
        resp = await self._client.post(
            "/api/v1/conclusions",
            json={
                "conclusion_key": conclusion_key,
                "requester_id": requester_id,
                "commitment_hash": commitment_hash.hex(),
            },
        )
        resp.raise_for_status()
        return _parse_conclusion_response(resp.json())

    async def get_conclusion(self, conclusion_key: str) -> ConclusionStatus:
        """Get the status of a blind conclusion."""
        resp = await self._client.get(f"/api/v1/conclusions/{conclusion_key}")
        resp.raise_for_status()
        return _parse_conclusion_response(resp.json())

    async def request_challenge(
        self, target_id: str, chain_id: str | None = None
    ) -> ChallengeInfo:
        """Request a liveness challenge."""
        body: dict[str, str] = {"target_id": target_id}
        if chain_id:
            body["chain_id"] = chain_id
        resp = await self._client.post("/api/v1/challenges", json=body)
        resp.raise_for_status()
        data = resp.json()
        return ChallengeInfo(
            challenge_id=data["challenge_id"],
            nonce_hex=data["nonce_hex"],
            deadline=datetime.fromisoformat(data["deadline"]),
            chain_id=data.get("chain_id"),
        )

    async def respond_challenge(
        self, challenge_id: str, requester_id: str, response_block_hash: bytes
    ) -> tuple[bool, str | None]:
        """Respond to a liveness challenge.

        Returns (passed, seal_id).
        """
        resp = await self._client.post(
            f"/api/v1/challenges/{challenge_id}/respond",
            json={
                "requester_id": requester_id,
                "response_block_hash": response_block_hash.hex(),
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["passed"], data.get("seal_id")


class SyncWitnessClient:
    """Synchronous wrapper around WitnessClient.

    For use in non-async contexts. Each method runs the async
    version in a new event loop.

    Usage::

        client = SyncWitnessClient("https://witness.synpareia.com")
        seal = client.timestamp_seal(my_profile.id, block.content_hash)
        client.close()
    """

    def __init__(self, base_url: str, *, timeout: float = 10.0) -> None:
        self._async_client = WitnessClient(base_url, timeout=timeout)

    def close(self) -> None:
        asyncio.get_event_loop().run_until_complete(self._async_client.close())

    def get_witness_info(self) -> WitnessInfo:
        return asyncio.get_event_loop().run_until_complete(self._async_client.get_witness_info())

    def timestamp_seal(self, requester_id: str, block_hash: bytes) -> SealPayload:
        return asyncio.get_event_loop().run_until_complete(
            self._async_client.timestamp_seal(requester_id, block_hash)
        )

    def state_seal(self, requester_id: str, chain_id: str, chain_head: bytes) -> SealPayload:
        return asyncio.get_event_loop().run_until_complete(
            self._async_client.state_seal(requester_id, chain_id, chain_head)
        )

    def submit_conclusion(
        self, conclusion_key: str, requester_id: str, commitment_hash: bytes
    ) -> ConclusionStatus:
        return asyncio.get_event_loop().run_until_complete(
            self._async_client.submit_conclusion(conclusion_key, requester_id, commitment_hash)
        )

    def get_conclusion(self, conclusion_key: str) -> ConclusionStatus:
        return asyncio.get_event_loop().run_until_complete(
            self._async_client.get_conclusion(conclusion_key)
        )

    def request_challenge(self, target_id: str, chain_id: str | None = None) -> ChallengeInfo:
        return asyncio.get_event_loop().run_until_complete(
            self._async_client.request_challenge(target_id, chain_id)
        )

    def respond_challenge(
        self, challenge_id: str, requester_id: str, response_block_hash: bytes
    ) -> tuple[bool, str | None]:
        return asyncio.get_event_loop().run_until_complete(
            self._async_client.respond_challenge(challenge_id, requester_id, response_block_hash)
        )


def _parse_seal_response(data: dict[str, Any]) -> SealPayload:
    """Parse a seal API response into a SealPayload."""
    target_block_hash = None
    if data.get("target_block_hash"):
        target_block_hash = bytes.fromhex(data["target_block_hash"])

    target_chain_head = None
    if data.get("target_chain_head"):
        target_chain_head = bytes.fromhex(data["target_chain_head"])

    return SealPayload(
        witness_id=data["witness_id"],
        witness_signature=base64.b64decode(data["witness_signature_b64"]),
        seal_type=SealType(data["seal_type"]),
        sealed_at=datetime.fromisoformat(data["sealed_at"]),
        target_block_hash=target_block_hash,
        target_chain_id=data.get("target_chain_id"),
        target_chain_head=target_chain_head,
    )


def _parse_conclusion_response(data: dict[str, Any]) -> ConclusionStatus:
    """Parse a conclusion API response."""
    party_a = data.get("party_a") or {}
    party_b = data.get("party_b") or {}
    return ConclusionStatus(
        conclusion_key=data["conclusion_key"],
        status=data["status"],
        party_a_commitment=party_a.get("commitment_hash"),
        party_b_commitment=party_b.get("commitment_hash"),
        party_a_seal_id=party_a.get("seal_id"),
        party_b_seal_id=party_b.get("seal_id"),
    )
