"""Regression tests for red-team findings.

Findings F1-F7 were reported in qa/reviews/sdk-chain-policy-redteam-2026-04-21.md.
Findings R1-R5 (and the R6/R7/R8 companions) were reported in
qa/reviews/sdk-redteam-2026-04-21.md (second pass, same day).

Keep this file as a living regression harness — when a new red-team
pass finds an issue, land the fix alongside a test here.
"""

from __future__ import annotations

import copy
from dataclasses import replace
from datetime import UTC, datetime

import pytest

import synpareia
from synpareia import (
    BlockProposal,
    assemble_block,
    create_threshold_commitment,
    start_proposal,
    verify_block,
)
from synpareia.block import Block
from synpareia.chain.export import verify_export, verify_export_structure
from synpareia.chain.operations import chain_from_export
from synpareia.policy import acceptance_bytes, templates
from synpareia.policy.model import PerBlockRule, Policy, Signatory
from synpareia.types import BlockType


class TestVerifyChainKeysRequired:
    """F1: verify_chain must fail closed when signed blocks lack public_keys.

    Prior behaviour silently skipped signature verification and returned
    True for chains with unchecked signatures.
    """

    def test_signed_chain_without_keys_fails_closed(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "signed"))
        valid, errors = chain.verify()
        assert not valid
        assert any("public_keys" in e for e in errors)

    def test_signed_chain_with_keys_passes(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "signed"))
        valid, errors = chain.verify(public_keys={profile.id: profile.public_key})
        assert valid, errors

    def test_structure_only_check_is_opt_in(self, profile: synpareia.Profile) -> None:
        """verify_chain_structure explicitly skips signatures — must stay separate."""
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "signed"))
        valid, errors = synpareia.verify_chain_structure(chain)
        assert valid, errors


class TestMetadataInSigningEnvelope:
    """F2: Block.metadata must be bound by the signature.

    Prior envelope only covered {id, type, author_id, content_hash,
    created_at}, leaving metadata freely tamperable post-signing.
    """

    def test_metadata_tamper_invalidates_signature(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(profile, BlockType.MESSAGE, "hi", metadata={"role": "peer"})
        assert verify_block(block, profile.public_key)

        tampered = replace(block, metadata={"role": "admin"})
        assert not verify_block(tampered, profile.public_key)


class TestCosignersInSigningEnvelope:
    """F3: Injecting a cosigner post-assembly must invalidate the signature."""

    def test_cosigner_injection_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        block = synpareia.create_block(profile, BlockType.MESSAGE, "solo")
        # Forge a co-signature entry — the primary signature doesn't cover it
        # only if the envelope excludes cosigners. With F3 in place, verify fails.
        forged = replace(block, co_signatures=((profile_b.id, b"\x00" * 64),))
        assert not verify_block(
            forged,
            profile.public_key,
            cosigner_public_keys={profile_b.id: profile_b.public_key},
        )

    def test_placeholder_cosigs_bind_envelope(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """start_proposal seeds co_signatures with placeholders so the envelope
        commits to the cosigner set from the outset."""
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        assert profile_b.id in {did for did, _ in prop.block.co_signatures}


class TestAmendmentRejected:
    """F4: AMENDMENT blocks are reserved for a future phase — reject at verify.

    Prior code left AMENDMENT silently accepted because no handler
    existed, even though templates advertised it as permitted.
    """

    def test_amendment_block_rejected(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.AMENDMENT, "change"))
        valid, errors = chain.verify(public_keys={profile.id: profile.public_key})
        assert not valid
        assert any("AMENDMENT" in e for e in errors)


class TestProposerDidBindsAuthorId:
    """F5: BlockProposal.proposer_did must equal block.author_id."""

    def test_mismatched_proposer_raises(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        skeleton = Block(
            id="blk_test",
            type=BlockType.MESSAGE,
            author_id=profile.id,
            content_hash=b"\x00" * 32,
            created_at=synpareia.create_block(profile, BlockType.MESSAGE, "x").created_at,
            co_signatures=((profile_b.id, b""),),
        )
        with pytest.raises(ValueError, match="proposer_did"):
            BlockProposal(
                block=skeleton,
                proposer_did=profile_b.id,  # does NOT match author_id
                required_signers=frozenset({profile.id, profile_b.id}),
            )


class TestPlaceholderDidsMatchRequired:
    """F6: BlockProposal placeholder cosigs must equal required_signers - proposer."""

    def test_wrong_placeholders_raises(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        outsider = synpareia.generate()
        skeleton = Block(
            id="blk_test",
            type=BlockType.MESSAGE,
            author_id=profile.id,
            content_hash=b"\x00" * 32,
            created_at=synpareia.create_block(profile, BlockType.MESSAGE, "x").created_at,
            # outsider is not a required signer, yet appears as cosigner
            co_signatures=((outsider.id, b""),),
        )
        with pytest.raises(ValueError, match="required_signers minus the proposer"):
            BlockProposal(
                block=skeleton,
                proposer_did=profile.id,
                required_signers=frozenset({profile.id, profile_b.id}),
            )

    def test_assemble_block_verifies_every_signature(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """assemble_block must reject a proposal whose signature bytes
        are present but don't verify against the envelope."""
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        # Replace profile_b's signature with bogus bytes but mark it present.
        bogus = dict(prop.signatures)
        bogus[profile_b.id] = b"\x00" * 64
        tampered = replace(prop, signatures=bogus)
        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        with pytest.raises(ValueError, match="fails verification"):
            assemble_block(tampered, public_keys=keys)


class TestThresholdFootguns:
    """F7: Threshold commitments must reject short shares and all-zero joint nonces."""

    def test_all_zero_joint_rejected(self) -> None:
        """Two identical shares XOR to zero — silent degradation to
        unseeded H(content). Reject explicitly."""
        share = b"\x11" * 32
        with pytest.raises(ValueError, match="all-zero joint nonce"):
            create_threshold_commitment(b"content", [share, share])

    def test_short_shares_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least 16 bytes"):
            synpareia.random_shares(2, length=8)


# ----- Second red-team pass (R1-R7) -------------------------------------


class TestExportPreservesCosignatures:
    """R1: export_chain/_import_chain must round-trip co_signatures.

    Prior behaviour silently dropped co_signatures from the exported JSON,
    so primary signatures (which commit to cosigners_hash) failed to
    verify after re-import.
    """

    def test_cosigned_block_round_trips(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        sphere = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))
        # Bob accepts so the chain is ACTIVE
        bob_accept = synpareia.create_block(
            profile_b,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=sphere.id,
                policy_hash=sphere.policy_hash,
                signatory_did=profile_b.id,
                accepted_at=datetime.now(UTC),
            ),
        )
        sphere.append(bob_accept)

        # Build a cosigned block via BlockProposal
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint statement",
            required_signers={profile.id, profile_b.id},
        )
        prop = synpareia.sign_proposal(prop, profile_b)
        block = assemble_block(
            prop,
            public_keys={profile.id: profile.public_key, profile_b.id: profile_b.public_key},
        )
        sphere.append(block)

        exported = synpareia.export_chain(sphere)
        # The exported JSON must carry the cosigs
        cosigned = [p for p in exported["positions"] if "co_signatures" in p["block"]]
        assert cosigned, "export dropped co_signatures"

        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        valid, errors = verify_export(exported, public_keys=keys)
        assert valid, errors

        imported = chain_from_export(exported)
        v, e = imported.verify(public_keys=keys)
        assert v, e


class TestLifecyclePayloadsBindChainId:
    """R2: ACCEPTANCE / ACK / CONCLUSION payloads must include chain_id.

    Prior behaviour bound only to policy_hash, letting an attacker replay
    a lifecycle block from chain A into chain B when the two shared a
    policy hash.
    """

    def test_acceptance_replay_across_chains_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain_a = synpareia.create_chain(profile, policy=policy)
        chain_b = synpareia.create_chain(profile, policy=policy)
        assert chain_a.policy_hash == chain_b.policy_hash
        assert chain_a.id != chain_b.id

        # Bob accepts chain_a
        accept_a = synpareia.create_block(
            profile_b,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain_a.id,
                policy_hash=chain_a.policy_hash,
                signatory_did=profile_b.id,
                accepted_at=datetime.now(UTC),
            ),
        )
        chain_a.append(accept_a)

        # Replaying the exact same block onto chain_b must fail policy verification
        chain_b.append(accept_a)
        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        valid, errors = chain_b.verify(public_keys=keys)
        assert not valid
        assert any("chain_id" in e for e in errors)


class TestUnsignedLifecycleBlocksRejected:
    """R3: ACCEPTANCE / ACK / CONCLUSION must carry a signature regardless
    of whether the policy emits a PerBlockRule for them.
    """

    def test_unsigned_acceptance_fails_verify(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        chain = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))
        unsigned = synpareia.create_block(
            profile_b,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain.id,
                policy_hash=chain.policy_hash,
                signatory_did=profile_b.id,
                accepted_at=datetime.now(UTC),
            ),
            sign=False,
        )
        chain.append(unsigned)
        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        valid, errors = chain.verify(public_keys=keys)
        assert not valid
        assert any("must be signed" in e for e in errors)


class TestCosignerBytesVerifiedByChain:
    """R4: verify_chain must forward public_keys so cosignature bytes are checked."""

    def test_tampered_cosig_byte_rejected(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        sphere = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))
        sphere.append(
            synpareia.create_block(
                profile_b,
                BlockType.ACCEPTANCE,
                acceptance_bytes(
                    chain_id=sphere.id,
                    policy_hash=sphere.policy_hash,
                    signatory_did=profile_b.id,
                    accepted_at=datetime.now(UTC),
                ),
            )
        )
        prop = start_proposal(
            profile,
            BlockType.MESSAGE,
            "joint",
            required_signers={profile.id, profile_b.id},
        )
        prop = synpareia.sign_proposal(prop, profile_b)
        block = assemble_block(
            prop,
            public_keys={profile.id: profile.public_key, profile_b.id: profile_b.public_key},
        )
        sphere.append(block)

        # Flip a byte in the cosignature bytes stored in the block object
        stored = sphere._store.get_block(block.id)
        assert stored is not None and stored.co_signatures
        did, sig = stored.co_signatures[0]
        tampered_sig = bytearray(sig)
        tampered_sig[0] ^= 0x01
        object.__setattr__(stored, "co_signatures", ((did, bytes(tampered_sig)),))

        keys = {profile.id: profile.public_key, profile_b.id: profile_b.public_key}
        valid, errors = sphere.verify(public_keys=keys)
        assert not valid
        assert any("signature verification failed" in e for e in errors)


class TestVerifyExportFailsClosedOnSignatures:
    """R5: verify_export must verify Ed25519 signatures when keys are supplied
    and must fail closed when signatures are present but keys are not.
    """

    def test_tampered_signature_fails(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "x"))
        data = synpareia.export_chain(chain)
        data = copy.deepcopy(data)
        sig_hex = data["positions"][1]["block"]["signature"]
        sig_bytes = bytearray(bytes.fromhex(sig_hex))
        sig_bytes[0] ^= 0x01
        data["positions"][1]["block"]["signature"] = sig_bytes.hex()
        valid, errors = verify_export(data, public_keys={profile.id: profile.public_key})
        assert not valid
        assert any("signature verification failed" in e for e in errors)

    def test_signed_export_without_keys_fails_closed(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "x"))
        data = synpareia.export_chain(chain)
        valid, errors = verify_export(data)
        assert not valid
        assert any("public_keys not supplied" in e for e in errors)

    def test_verify_export_structure_skips_signatures(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "x"))
        data = synpareia.export_chain(chain)
        errors = verify_export_structure(data)
        assert errors == []


class TestPolicyVersionValidated:
    """R7: verify_chain_policy must reject unsupported policy versions."""

    def test_unknown_version_rejected(self, profile: synpareia.Profile) -> None:
        bad_policy = Policy(
            chain_type="cop",
            version="v99",
            signatories=(Signatory(did=profile.id, role="owner"),),
            block_types_permitted=("policy", "message"),
            per_block_rules=(
                PerBlockRule(
                    block_type="message",
                    authors=(f"signatory:{profile.id}",),
                    signature_required=True,
                ),
            ),
        )
        chain = synpareia.create_chain(profile, policy=bad_policy)
        valid, errors = chain.verify(public_keys={profile.id: profile.public_key})
        assert not valid
        assert any("unsupported policy version" in e for e in errors)
