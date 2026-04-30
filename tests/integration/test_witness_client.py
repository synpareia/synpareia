"""Integration test: SDK WitnessClient against the witness service.

These tests require the witness service source to be available (monorepo layout).
They are automatically skipped when running from the standalone SDK repo.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pytest_asyncio

import synpareia
from synpareia.policy import templates
from synpareia.seal.verify import verify_seal
from synpareia.witness.client import WitnessClient

# Add witness service to path for test app creation (monorepo layout)
_witness_src = Path(__file__).parent.parent.parent.parent / "witness" / "src"
if _witness_src.is_dir():
    sys.path.insert(0, str(_witness_src))

try:
    import slowapi  # noqa: F401, E402
    from witness.config import WitnessConfig  # noqa: F401, E402

    HAS_WITNESS_SERVICE = True
except ImportError:
    HAS_WITNESS_SERVICE = False

pytestmark = pytest.mark.skipif(
    not HAS_WITNESS_SERVICE,
    reason="Witness service not available (standalone SDK repo, or witness deps not in SDK venv)",
)


@pytest_asyncio.fixture
async def witness_app(tmp_path):
    """Create a witness test app."""
    from witness.config import WitnessConfig
    from witness.main import create_app

    config = WitnessConfig(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/test.db",
        witness_key_path=tmp_path / "witness.key",
        access_token=None,
    )
    app = create_app(config)
    async with app.router.lifespan_context(app):
        yield app


@pytest_asyncio.fixture
async def client(witness_app):
    """WitnessClient backed by the test app."""
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=witness_app)
    http_client = AsyncClient(transport=transport, base_url="http://test")
    witness_client = WitnessClient.__new__(WitnessClient)
    witness_client._base_url = "http://test"
    witness_client._client = http_client
    yield witness_client
    await http_client.aclose()


@pytest.mark.asyncio
async def test_full_workflow(client: WitnessClient) -> None:
    """End-to-end: create chain, request seal, verify offline."""
    # Create a profile and chain
    profile = synpareia.generate()
    chain = synpareia.create_chain(profile, policy=templates.cop(profile))

    # Add a block
    block = synpareia.create_block(profile, "message", "Hello, witness!")
    chain.append(block)

    # Get witness info (for offline verification later)
    info = await client.get_witness_info()
    assert info.witness_id.startswith("did:synpareia:")

    # Request a timestamp seal on the block (no requester identity sent)
    seal = await client.timestamp_seal(block.content_hash)
    assert seal.seal_type == "timestamp"
    assert seal.target_block_hash == block.content_hash

    # Verify the seal offline
    valid, err = verify_seal(seal, info.public_key)
    assert valid, f"Seal verification failed: {err}"

    # Append seal to chain as a seal block
    seal_block = synpareia.create_seal_block(seal)
    chain.append(seal_block)
    # POLICY (genesis) + message + seal = 3
    assert chain.length == 3

    # Request a state seal on the chain
    state_seal = await client.state_seal(chain.id, chain.head_hash)
    assert state_seal.seal_type == "state"
    assert state_seal.target_chain_id == chain.id
    assert state_seal.target_chain_head == chain.head_hash

    valid, err = verify_seal(state_seal, info.public_key)
    assert valid, f"State seal verification failed: {err}"


@pytest.mark.asyncio
async def test_blind_conclusion_flow(client: WitnessClient) -> None:
    """Two profiles do a blind conclusion through the client."""
    profile_a = synpareia.generate()
    profile_b = synpareia.generate()

    content_a = b"Rating: 4 out of 5"
    content_b = b"Rating: 3 out of 5"

    commitment_a, nonce_a = synpareia.create_commitment(content_a)
    commitment_b, nonce_b = synpareia.create_commitment(content_b)

    key = "test_sdk_conclusion"

    # Party A submits
    status = await client.submit_conclusion(key, profile_a.id, commitment_a)
    assert status.status == "waiting"

    # Party B submits
    status = await client.submit_conclusion(key, profile_b.id, commitment_b)
    assert status.status == "ready"
    assert status.party_a_commitment == commitment_a.hex()
    assert status.party_b_commitment == commitment_b.hex()

    # Both can now verify each other's commitments locally
    assert synpareia.verify_commitment(commitment_a, content_a, nonce_a)
    assert synpareia.verify_commitment(commitment_b, content_b, nonce_b)


@pytest.mark.asyncio
async def test_liveness_challenge(client: WitnessClient) -> None:
    """Request and respond to a liveness challenge."""
    profile = synpareia.generate()
    chain = synpareia.create_chain(profile, policy=templates.cop(profile))

    # Request challenge
    challenge = await client.request_challenge(profile.id, chain.id)
    assert challenge.nonce_hex
    assert challenge.chain_id == chain.id

    # Create a response block containing the nonce
    block = synpareia.create_block(profile, "system", f"liveness:{challenge.nonce_hex}")
    chain.append(block)

    # Respond
    passed, seal_id = await client.respond_challenge(
        challenge.challenge_id, profile.id, block.content_hash
    )
    assert passed
    assert seal_id is not None
