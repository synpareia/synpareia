"""Tests for the seal module — SealPayload, create_seal, verify_seal."""

from __future__ import annotations

from datetime import UTC, datetime

import synpareia
from synpareia.identity import generate
from synpareia.seal import SealPayload, create_seal, create_seal_block, seal_signing_envelope
from synpareia.seal.verify import verify_seal, verify_seal_block
from synpareia.types import BlockType, SealType


class TestSealPayload:
    def test_create_timestamp_seal(self) -> None:
        witness = generate()
        block_hash = b"\xab" * 32

        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=block_hash,
        )

        assert seal.witness_id == witness.id
        assert seal.seal_type == SealType.TIMESTAMP
        assert seal.target_block_hash == block_hash
        assert seal.target_chain_id is None
        assert seal.target_chain_head is None
        assert len(seal.witness_signature) == 64
        assert seal.sealed_at.tzinfo is not None

    def test_create_state_seal(self) -> None:
        witness = generate()
        chain_head = b"\xcd" * 32

        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.STATE,
            target_chain_id="chn_abc123",
            target_chain_head=chain_head,
        )

        assert seal.seal_type == SealType.STATE
        assert seal.target_chain_id == "chn_abc123"
        assert seal.target_chain_head == chain_head
        assert seal.target_block_hash is None

    def test_seal_with_metadata(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.RECEIPT,
            target_block_hash=b"\x00" * 32,
            metadata={"requester": "did:synpareia:someone"},
        )
        assert seal.metadata["requester"] == "did:synpareia:someone"

    def test_seal_payload_is_frozen(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=b"\x00" * 32,
        )
        try:
            seal.seal_type = "tampered"  # type: ignore[misc]
            raise AssertionError("Should have raised AttributeError")
        except AttributeError:
            pass


class TestVerifySeal:
    def test_valid_timestamp_seal(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=b"\xab" * 32,
        )

        valid, err = verify_seal(seal, witness.public_key)
        assert valid
        assert err is None

    def test_valid_state_seal(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.STATE,
            target_chain_id="chn_test",
            target_chain_head=b"\xcd" * 32,
        )

        valid, err = verify_seal(seal, witness.public_key)
        assert valid
        assert err is None

    def test_wrong_key_rejects(self) -> None:
        witness = generate()
        other = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=b"\xab" * 32,
        )

        valid, err = verify_seal(seal, other.public_key)
        assert not valid
        assert "verification failed" in err

    def test_tampered_seal_type_rejects(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=b"\xab" * 32,
        )
        # Tamper with seal type
        tampered = SealPayload(
            witness_id=seal.witness_id,
            witness_signature=seal.witness_signature,
            seal_type=SealType.STATE,  # changed
            sealed_at=seal.sealed_at,
            target_block_hash=seal.target_block_hash,
        )

        valid, err = verify_seal(tampered, witness.public_key)
        assert not valid

    def test_tampered_timestamp_rejects(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=b"\xab" * 32,
        )
        tampered = SealPayload(
            witness_id=seal.witness_id,
            witness_signature=seal.witness_signature,
            seal_type=seal.seal_type,
            sealed_at=datetime(2020, 1, 1, tzinfo=UTC),  # changed
            target_block_hash=seal.target_block_hash,
        )

        valid, err = verify_seal(tampered, witness.public_key)
        assert not valid

    def test_tampered_block_hash_rejects(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=b"\xab" * 32,
        )
        tampered = SealPayload(
            witness_id=seal.witness_id,
            witness_signature=seal.witness_signature,
            seal_type=seal.seal_type,
            sealed_at=seal.sealed_at,
            target_block_hash=b"\xff" * 32,  # changed
        )

        valid, err = verify_seal(tampered, witness.public_key)
        assert not valid


class TestVerifySealBlock:
    def test_matching_target(self) -> None:
        witness = generate()
        block_hash = b"\xab" * 32
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=block_hash,
        )

        valid, err = verify_seal_block(seal, witness.public_key, expected_block_hash=block_hash)
        assert valid
        assert err is None

    def test_wrong_block_hash(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=b"\xab" * 32,
        )

        valid, err = verify_seal_block(seal, witness.public_key, expected_block_hash=b"\xff" * 32)
        assert not valid
        assert "block hash" in err

    def test_wrong_chain_id(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.STATE,
            target_chain_id="chn_actual",
            target_chain_head=b"\xcd" * 32,
        )

        valid, err = verify_seal_block(seal, witness.public_key, expected_chain_id="chn_expected")
        assert not valid
        assert "chain" in err

    def test_wrong_chain_head(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.STATE,
            target_chain_id="chn_test",
            target_chain_head=b"\xcd" * 32,
        )

        valid, err = verify_seal_block(seal, witness.public_key, expected_chain_head=b"\xff" * 32)
        assert not valid
        assert "chain head" in err


class TestCreateSealBlock:
    def test_creates_valid_block(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=b"\xab" * 32,
        )
        block = create_seal_block(seal)

        assert block.type == BlockType.SEAL
        assert block.author_id == witness.id
        assert block.content is not None
        assert block.signature == seal.witness_signature
        assert block.id.startswith("blk_")
        assert block.metadata["seal_type"] == "timestamp"
        assert "target_block_hash" in block.metadata

    def test_seal_block_verifiable(self) -> None:
        """Seal block's signature is verifiable against the witness's public key."""
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=b"\xab" * 32,
        )
        block = create_seal_block(seal)

        # The block's content is the canonical envelope, and signature is the witness's
        from synpareia.signing import verify as ed25519_verify

        assert ed25519_verify(witness.public_key, block.content, block.signature)

    def test_seal_block_appendable_to_chain(self) -> None:
        """Seal blocks can be appended to any chain."""
        from synpareia.policy import templates

        profile = generate()
        witness = generate()

        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.TIMESTAMP,
            target_block_hash=b"\xab" * 32,
        )
        block = create_seal_block(seal)
        pos = chain.append(block)

        # Position 1 is the POLICY genesis block; seal lands at 2.
        assert pos.sequence == 2
        assert chain.length == 2

    def test_state_seal_block_metadata(self) -> None:
        witness = generate()
        seal = create_seal(
            witness.private_key,
            witness.id,
            SealType.STATE,
            target_chain_id="chn_test",
            target_chain_head=b"\xcd" * 32,
        )
        block = create_seal_block(seal)

        assert block.metadata["seal_type"] == "state"
        assert block.metadata["target_chain_id"] == "chn_test"
        assert "target_chain_head" in block.metadata


class TestSealSigningEnvelope:
    def test_deterministic(self) -> None:
        """Same inputs produce same canonical bytes."""
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        a = seal_signing_envelope(
            SealType.TIMESTAMP, "did:synpareia:abc", ts, target_block_hash=b"\xab" * 32
        )
        b = seal_signing_envelope(
            SealType.TIMESTAMP, "did:synpareia:abc", ts, target_block_hash=b"\xab" * 32
        )
        assert a == b

    def test_different_inputs_differ(self) -> None:
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        a = seal_signing_envelope(
            SealType.TIMESTAMP, "did:synpareia:abc", ts, target_block_hash=b"\xab" * 32
        )
        b = seal_signing_envelope(
            SealType.STATE, "did:synpareia:abc", ts, target_block_hash=b"\xab" * 32
        )
        assert a != b
