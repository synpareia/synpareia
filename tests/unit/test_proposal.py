"""Tests for BlockProposal — multi-party block negotiation."""

from __future__ import annotations

import pytest

import synpareia
from synpareia import (
    BlockProposal,
    assemble_block,
    sign_proposal,
    start_proposal,
    verify_block,
    verify_proposal,
)
from synpareia.types import BlockType


class TestStartProposal:
    def test_proposer_signature_added(self, profile: synpareia.Profile) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint statement",
            required_signers={profile.id},
        )
        assert profile.id in prop.signatures
        assert prop.proposer_did == profile.id
        assert prop.block.author_id == profile.id

    def test_proposer_must_be_required_signer(self, profile: synpareia.Profile) -> None:
        other = synpareia.generate()
        with pytest.raises(ValueError, match="proposer DID must be included"):
            start_proposal(
                profile,
                BlockType.MESSAGE,
                "bad",
                required_signers={other.id},
            )

    def test_public_only_profile_rejected(self, profile: synpareia.Profile) -> None:
        public_only = synpareia.from_public_key(profile.public_key)
        with pytest.raises(ValueError, match="private key"):
            start_proposal(
                public_only,
                BlockType.MESSAGE,
                "no",
                required_signers={public_only.id},
            )


class TestSignProposal:
    def test_cosigner_adds_signature(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "co-authored",
            required_signers={profile.id, profile_b.id},
        )
        signed = sign_proposal(prop, profile_b)
        assert set(signed.signatures.keys()) == {profile.id, profile_b.id}

    def test_non_required_signer_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        outsider = synpareia.generate()
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "co-authored",
            required_signers={profile.id, profile_b.id},
        )
        with pytest.raises(ValueError, match="not in required_signers"):
            sign_proposal(prop, outsider)

    def test_repeated_signature_overwrites(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """Signing twice is idempotent for the same signer."""
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        once = sign_proposal(prop, profile_b)
        twice = sign_proposal(once, profile_b)
        # Sigs are Ed25519 (deterministic under the same message+key) so equal.
        assert once.signatures[profile_b.id] == twice.signatures[profile_b.id]


class TestVerifyProposal:
    def test_all_valid_signatures_verify(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        prop = sign_proposal(prop, profile_b)
        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        assert verify_proposal(prop, keys)

    def test_missing_key_fails_verification(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        prop = sign_proposal(prop, profile_b)
        # Map only profile_b; profile's signature has no key to verify against.
        assert not verify_proposal(prop, {profile_b.id: profile_b.public_key})

    def test_wrong_key_fails_verification(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        prop = sign_proposal(prop, profile_b)
        bad_keys = {
            profile.id: profile_b.public_key,  # swapped
            profile_b.id: profile.public_key,
        }
        assert not verify_proposal(prop, bad_keys)


class TestAssembleBlock:
    def test_all_signers_present_assembles(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        prop = sign_proposal(prop, profile_b)
        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        block = assemble_block(prop, public_keys=keys)
        assert block.author_id == profile.id
        assert block.signature is not None
        assert len(block.co_signatures) == 1
        assert block.co_signatures[0][0] == profile_b.id

    def test_missing_signer_raises(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        with pytest.raises(ValueError, match="missing signatures"):
            assemble_block(prop, public_keys=keys)

    def test_assembled_block_verifies_with_all_keys(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        prop = sign_proposal(prop, profile_b)
        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        block = assemble_block(prop, public_keys=keys)

        assert verify_block(
            block,
            profile.public_key,
            cosigner_public_keys={profile_b.id: profile_b.public_key},
        )

    def test_assembled_block_tampered_content_fails(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        from dataclasses import replace

        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        prop = sign_proposal(prop, profile_b)
        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        block = assemble_block(prop, public_keys=keys)

        tampered = replace(block, content=b"something else")
        # content_hash no longer matches content
        assert not verify_block(tampered, profile.public_key)

    def test_wrong_cosigner_key_fails_verification(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        prop = sign_proposal(prop, profile_b)
        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        block = assemble_block(prop, public_keys=keys)

        # Supply a key that doesn't match profile_b
        outsider = synpareia.generate()
        assert not verify_block(
            block,
            profile.public_key,
            cosigner_public_keys={profile_b.id: outsider.public_key},
        )


class TestThreeParty:
    def test_three_party_proposal(self) -> None:
        alice = synpareia.generate()
        bob = synpareia.generate()
        carol = synpareia.generate()

        prop = start_proposal(
            alice,
            BlockType.MESSAGE,
            "joint statement from three parties",
            required_signers={alice.id, bob.id, carol.id},
        )
        prop = sign_proposal(prop, bob)
        prop = sign_proposal(prop, carol)

        keys = {
            alice.id: alice.public_key,
            bob.id: bob.public_key,
            carol.id: carol.public_key,
        }
        assert verify_proposal(prop, keys)

        block = assemble_block(prop, public_keys=keys)
        assert block.author_id == alice.id
        assert len(block.co_signatures) == 2
        # Cosigners are sorted by DID for determinism
        cosigner_dids = [did for did, _ in block.co_signatures]
        assert cosigner_dids == sorted(cosigner_dids)
        assert alice.id not in cosigner_dids

        cosigner_keys = {bob.id: bob.public_key, carol.id: carol.public_key}
        assert verify_block(block, alice.public_key, cosigner_public_keys=cosigner_keys)


class TestBlockProposalImmutability:
    def test_sign_returns_new_object(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        signed = sign_proposal(prop, profile_b)
        # Original proposal's signatures dict should not have been mutated.
        assert profile_b.id not in prop.signatures
        assert profile_b.id in signed.signatures


class TestProposalTypeAnnotation:
    def test_is_block_proposal(self, profile: synpareia.Profile) -> None:
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "solo",
            required_signers={profile.id},
        )
        assert isinstance(prop, BlockProposal)
