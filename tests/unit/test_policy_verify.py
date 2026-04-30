"""Tests for verify_chain_policy() — standalone policy enforcement.

Covers the happy path and every structural/policy violation verify_chain_policy
must flag: disallowed block types, mismatched authors, missing signatures,
malformed ACCEPTANCE/ACK/CONCLUSION payloads, and misplaced POLICY blocks.

These tests exercise verify_chain_policy directly; they do not rely on it
being wired into verify_chain or append_block (Phase B is standalone).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

import synpareia
from synpareia.chain.operations import append_block
from synpareia.policy import (
    AmendmentRules,
    PerBlockRule,
    Retention,
    Signatory,
    WitnessDecl,
    acceptance_bytes,
    ack_bytes,
    conclusion_bytes,
    policy_hash,
    templates,
    verify_chain_policy,
)
from synpareia.types import BlockType, ChainType


class TestValidChains:
    def test_empty_cop_chain_passes(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        valid, errors = verify_chain_policy(chain)
        assert valid, errors

    def test_cop_chain_with_messages_passes(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        for i in range(3):
            chain.append(synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}"))
        valid, errors = verify_chain_policy(chain)
        assert valid, errors

    def test_cop_with_thought_and_reaction(self, profile: synpareia.Profile) -> None:
        """Permitted block types without a PerBlockRule are unrestricted."""
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.THOUGHT, "hmm"))
        chain.append(synpareia.create_block(profile, BlockType.REACTION, "!"))
        valid, errors = verify_chain_policy(chain)
        assert valid, errors

    def test_sphere_pending_chain_passes_policy_verify(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """Sphere chain with just genesis (still PENDING) is policy-valid."""
        chain = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))
        valid, errors = verify_chain_policy(chain)
        assert valid, errors

    def test_sphere_with_acceptance_passes(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)
        accept = synpareia.create_block(
            profile_b,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain.id,
                policy_hash=policy_hash(policy),
                signatory_did=profile_b.id,
                accepted_at=datetime.now(UTC),
            ),
        )
        chain.append(accept)
        valid, errors = verify_chain_policy(chain)
        assert valid, errors

    def test_conclusion_by_signatory_passes(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        conclusion = synpareia.create_block(
            profile,
            BlockType.CONCLUSION,
            conclusion_bytes(
                chain_id=chain.id,
                author_did=profile.id,
                concluded_at=datetime.now(UTC),
            ),
        )
        chain.append(conclusion)
        valid, errors = verify_chain_policy(chain)
        assert valid, errors


class TestBlockTypePermitted:
    def test_disallowed_block_type_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """AUDIT chains forbid MESSAGE blocks."""
        policy = templates.audit(profile, auditors=(profile_b,))
        chain = synpareia.create_chain(profile, policy=policy)
        bad = synpareia.create_block(profile, BlockType.MESSAGE, "not allowed here")
        chain.append(bad)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("not in policy.block_types_permitted" in e for e in errors)

    def test_restricted_to_message_only(self, profile: synpareia.Profile) -> None:
        """A custom policy permitting only MESSAGE rejects THOUGHT."""
        policy = templates.custom(
            version="1",
            chain_type=str(ChainType.CUSTOM),
            signatories=(Signatory(did=profile.id, role="owner"),),
            block_types_permitted=(
                str(BlockType.POLICY),
                str(BlockType.MESSAGE),
                str(BlockType.CONCLUSION),
            ),
            per_block_rules=(
                PerBlockRule(
                    block_type=str(BlockType.MESSAGE),
                    authors=("signatory:owner",),
                    signature_required=True,
                    retention=Retention(mode="indefinite"),
                ),
            ),
        )
        chain = synpareia.create_chain(profile, policy=policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "ok"))
        chain.append(synpareia.create_block(profile, BlockType.THOUGHT, "nope"))
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("thought" in e and "not in policy.block_types_permitted" in e for e in errors)


class TestAuthorEnforcement:
    def test_wrong_author_role_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """In a CoP, only the owner may author MESSAGE blocks."""
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        outsider = synpareia.create_block(profile_b, BlockType.MESSAGE, "intrusion")
        chain.append(outsider)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("does not match" in e for e in errors)

    def test_signatory_role_match(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """In a Sphere, either owner or counterparty may author MESSAGE."""
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)
        # Need ACCEPTANCE first for a well-formed lifecycle, but verify_chain_policy
        # is structural — it enforces author rules regardless of lifecycle state.
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "from owner"))
        chain.append(synpareia.create_block(profile_b, BlockType.MESSAGE, "from counterparty"))
        valid, errors = verify_chain_policy(chain)
        assert valid, errors

    def test_witness_did_match(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """witness:<did> selector authorises the named witness for SEAL blocks."""
        witness = synpareia.generate()
        policy = templates.sphere(profile, profile_b, witness=witness)
        chain = synpareia.create_chain(profile, policy=policy)
        seal_block = synpareia.create_block(witness, BlockType.SEAL, b"seal-payload")
        chain.append(seal_block)
        valid, errors = verify_chain_policy(chain)
        assert valid, errors

    def test_non_witness_seal_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """A non-witness author for a SEAL block is rejected."""
        witness = synpareia.generate()
        policy = templates.sphere(profile, profile_b, witness=witness)
        chain = synpareia.create_chain(profile, policy=policy)
        impostor = synpareia.create_block(profile_b, BlockType.SEAL, b"impostor-seal")
        chain.append(impostor)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("does not match" in e and "seal" in e.lower() for e in errors)


class TestSignatureRequirement:
    def test_unsigned_block_when_required_rejected(self, profile: synpareia.Profile) -> None:
        """signature_required=True with an unsigned block fails."""
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        unsigned = synpareia.create_block(profile, BlockType.MESSAGE, "unsigned", sign=False)
        chain.append(unsigned)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("signature required" in e for e in errors)

    def test_public_keys_verify_signatures(self, profile: synpareia.Profile) -> None:
        """When public_keys is provided, real crypto verification runs."""
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "hello"))
        keys = {profile.id: profile.public_key}
        valid, errors = verify_chain_policy(chain, public_keys=keys)
        assert valid, errors

    def test_public_keys_missing_for_signer_reports_error(
        self, profile: synpareia.Profile
    ) -> None:
        """Supplying public_keys without a key for the signer is a hard error."""
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "hello"))
        valid, errors = verify_chain_policy(chain, public_keys={})
        assert not valid
        assert any("no public key provided" in e for e in errors)

    def test_public_keys_wrong_key_fails(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """Wrong public key under a signer's DID fails verification."""
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "hello"))
        # Map the author's DID to a different key on purpose.
        keys = {profile.id: profile_b.public_key}
        valid, errors = verify_chain_policy(chain, public_keys=keys)
        assert not valid
        assert any("signature verification failed" in e for e in errors)


class TestAcceptancePayload:
    def test_acceptance_wrong_policy_hash_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)
        bad = synpareia.create_block(
            profile_b,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain.id,
                policy_hash=b"\x00" * 32,
                signatory_did=profile_b.id,
                accepted_at=datetime.now(UTC),
            ),
        )
        chain.append(bad)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("ACCEPTANCE.policy_hash" in e for e in errors)

    def test_acceptance_signatory_did_mismatch_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)
        bad = synpareia.create_block(
            profile_b,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain.id,
                policy_hash=policy_hash(policy),
                signatory_did=profile.id,  # lies about who is accepting
                accepted_at=datetime.now(UTC),
            ),
        )
        chain.append(bad)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("ACCEPTANCE.signatory_did" in e for e in errors)

    def test_acceptance_by_non_signatory_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)
        outsider = synpareia.generate()
        bad = synpareia.create_block(
            outsider,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain.id,
                policy_hash=policy_hash(policy),
                signatory_did=outsider.id,
                accepted_at=datetime.now(UTC),
            ),
        )
        chain.append(bad)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("is not a declared signatory" in e for e in errors)

    def test_acceptance_malformed_payload_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)
        bad = synpareia.create_block(profile_b, BlockType.ACCEPTANCE, b"not json")
        chain.append(bad)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("ACCEPTANCE payload is malformed" in e for e in errors)


class TestAckPayload:
    def test_ack_by_witness_passes(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        witness = synpareia.generate()
        policy = templates.sphere(profile, profile_b, witness=witness)
        chain = synpareia.create_chain(profile, policy=policy)
        ack = synpareia.create_block(
            witness,
            BlockType.ACK,
            ack_bytes(
                chain_id=chain.id,
                policy_hash=policy_hash(policy),
                witness_did=witness.id,
                acked_at=datetime.now(UTC),
            ),
        )
        chain.append(ack)
        valid, errors = verify_chain_policy(chain)
        assert valid, errors

    def test_ack_by_non_witness_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)  # no witness
        chain = synpareia.create_chain(profile, policy=policy)
        bad = synpareia.create_block(
            profile,
            BlockType.ACK,
            ack_bytes(
                chain_id=chain.id,
                policy_hash=policy_hash(policy),
                witness_did=profile.id,
                acked_at=datetime.now(UTC),
            ),
        )
        chain.append(bad)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("is not a declared witness" in e for e in errors)


class TestConclusionPayload:
    def test_conclusion_by_non_signatory_rejected(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        outsider = synpareia.generate()
        bad = synpareia.create_block(
            outsider,
            BlockType.CONCLUSION,
            conclusion_bytes(
                chain_id=chain.id,
                author_did=outsider.id,
                concluded_at=datetime.now(UTC),
            ),
        )
        chain.append(bad)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("CONCLUSION author" in e and "not a declared signatory" in e for e in errors)

    def test_conclusion_author_mismatch_rejected(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        bad_content = conclusion_bytes(
            chain_id=chain.id,
            author_did="did:synpareia:bogus",
            concluded_at=datetime.now(UTC),
        )
        bad = synpareia.create_block(profile, BlockType.CONCLUSION, bad_content)
        chain.append(bad)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("CONCLUSION.author_did" in e for e in errors)


class TestPolicyBlockInvariants:
    def test_second_policy_block_rejected(self, profile: synpareia.Profile) -> None:
        """A second POLICY block anywhere past position 1 is rejected."""
        policy = templates.cop(profile)
        chain = synpareia.create_chain(profile, policy=policy)
        # Hand-craft a second POLICY block past position 1.
        second = synpareia.create_block(
            profile,
            BlockType.POLICY,
            synpareia.policy_canonical_bytes(policy),
        )
        append_block(chain, second)
        valid, errors = verify_chain_policy(chain)
        assert not valid
        assert any("POLICY block only allowed at position 1" in e for e in errors)
        assert any("multiple POLICY blocks" in e for e in errors)


class TestEmptyAndMissing:
    def test_chain_without_positions_fails(self, profile: synpareia.Profile) -> None:
        """A raw Chain with no positions fails loudly."""
        from synpareia.chain import Chain
        from synpareia.chain.storage import MemoryStore

        empty = Chain(
            id="chn_empty",
            owner_id=profile.id,
            chain_type=str(ChainType.COP),
            created_at=datetime.now(UTC),
            head_hash=None,
            metadata={},
            _store=MemoryStore(),
            policy_hash=None,
        )
        valid, errors = verify_chain_policy(empty)
        assert not valid
        assert any("no POLICY block at position 1" in e for e in errors)


class TestAmendmentRulesUnused:
    """AmendmentRules are not yet enforced by verify_chain_policy — document that."""

    def test_amendment_rules_present_but_not_enforced(self, profile: synpareia.Profile) -> None:
        """Amendment rule declarations should not affect verify_chain_policy in v1."""
        policy = replace(
            templates.cop(profile),
            amendment_rules=AmendmentRules(default="all_signatories_cosign"),
        )
        chain = synpareia.create_chain(profile, policy=policy)
        valid, errors = verify_chain_policy(chain)
        assert valid, errors


@pytest.mark.parametrize(
    "role_overrides",
    [
        (),  # default owner+counterparty
    ],
)
class TestRetentionDeclared:
    """Retention is declared in PerBlockRule but not enforced at block-append time.

    These tests confirm retention declarations don't cause verify failures.
    """

    def test_retention_indefinite_passes(
        self, profile: synpareia.Profile, role_overrides: tuple[object, ...]
    ) -> None:
        policy = templates.cop(profile)
        chain = synpareia.create_chain(profile, policy=policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "keep"))
        valid, errors = verify_chain_policy(chain)
        assert valid, errors


class TestWitnessDidSelector:
    def test_named_witness_can_seal(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """A witness identified in the policy can author SEAL blocks; others cannot."""
        witness = synpareia.generate()
        policy = templates.custom(
            version="1",
            chain_type=str(ChainType.SPHERE),
            signatories=(
                Signatory(did=profile.id, role="owner"),
                Signatory(did=profile_b.id, role="counterparty"),
            ),
            block_types_permitted=(
                str(BlockType.POLICY),
                str(BlockType.MESSAGE),
                str(BlockType.SEAL),
                str(BlockType.ACCEPTANCE),
                str(BlockType.ACK),
                str(BlockType.CONCLUSION),
            ),
            per_block_rules=(
                PerBlockRule(
                    block_type=str(BlockType.SEAL),
                    authors=(f"witness:{witness.id}",),
                    signature_required=True,
                ),
            ),
            witnesses=(WitnessDecl(did=witness.id, roles=("timestamp",)),),
        )
        chain = synpareia.create_chain(profile, policy=policy)
        chain.append(synpareia.create_block(witness, BlockType.SEAL, b"ts"))
        valid, errors = verify_chain_policy(chain)
        assert valid, errors
