"""Tests for chain lifecycle classification — PROPOSED/PENDING/ACTIVE/CONCLUDED."""

from __future__ import annotations

from datetime import UTC, datetime

import synpareia
from synpareia.policy import (
    acceptance_bytes,
    accepted_signatories,
    compute_lifecycle_state,
    conclusion_bytes,
    extract_policy,
    policy_hash,
    templates,
)
from synpareia.types import BlockType, LifecycleState


class TestExtractPolicy:
    def test_cop_chain_round_trip(self, profile: synpareia.Profile) -> None:
        policy = templates.cop(profile)
        chain = synpareia.create_chain(profile, policy=policy)
        recovered = extract_policy(chain)
        assert recovered == policy

    def test_sphere_chain_round_trip(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)
        recovered = extract_policy(chain)
        assert recovered == policy
        assert recovered.signatory_dids == policy.signatory_dids


class TestLifecycleCop:
    """Single-signatory CoP chains are ACTIVE at genesis."""

    def test_cop_is_active_from_genesis(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        assert compute_lifecycle_state(chain) == LifecycleState.ACTIVE
        assert chain.state == LifecycleState.ACTIVE

    def test_cop_with_conclusion_block(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        block = synpareia.create_block(
            profile,
            BlockType.CONCLUSION,
            conclusion_bytes(
                chain_id=chain.id,
                author_did=profile.id,
                concluded_at=datetime.now(UTC),
            ),
        )
        chain.append(block)
        assert compute_lifecycle_state(chain) == LifecycleState.CONCLUDED


class TestLifecycleSphere:
    """Sphere chains start PENDING until the counterparty accepts."""

    def test_sphere_starts_pending(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        chain = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))
        assert compute_lifecycle_state(chain) == LifecycleState.PENDING

    def test_sphere_becomes_active_after_counterparty_accepts(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)

        accept_block = synpareia.create_block(
            profile_b,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain.id,
                policy_hash=policy_hash(policy),
                signatory_did=profile_b.id,
                accepted_at=datetime.now(UTC),
            ),
        )
        chain.append(accept_block)
        assert compute_lifecycle_state(chain) == LifecycleState.ACTIVE

    def test_proposer_acceptance_is_implicit(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)
        accepted = accepted_signatories(chain, policy)
        # Proposer signed the POLICY block — that's implicit acceptance.
        assert profile.id in accepted
        assert profile_b.id not in accepted

    def test_sphere_concluded_after_conclusion_block(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)

        accept_block = synpareia.create_block(
            profile_b,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain.id,
                policy_hash=policy_hash(policy),
                signatory_did=profile_b.id,
                accepted_at=datetime.now(UTC),
            ),
        )
        chain.append(accept_block)

        conclusion_block = synpareia.create_block(
            profile,
            BlockType.CONCLUSION,
            conclusion_bytes(
                chain_id=chain.id,
                author_did=profile.id,
                concluded_at=datetime.now(UTC),
            ),
        )
        chain.append(conclusion_block)
        assert compute_lifecycle_state(chain) == LifecycleState.CONCLUDED


class TestAcceptanceValidation:
    """Malformed or mis-targeted ACCEPTANCE blocks must not count."""

    def test_acceptance_with_wrong_policy_hash_ignored(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)

        bogus_accept = synpareia.create_block(
            profile_b,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain.id,
                policy_hash=b"\x00" * 32,  # not our policy
                signatory_did=profile_b.id,
                accepted_at=datetime.now(UTC),
            ),
        )
        chain.append(bogus_accept)
        assert compute_lifecycle_state(chain) == LifecycleState.PENDING

    def test_acceptance_signed_by_non_signatory_ignored(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)

        outsider = synpareia.generate()
        bogus_accept = synpareia.create_block(
            outsider,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain.id,
                policy_hash=policy_hash(policy),
                signatory_did=outsider.id,
                accepted_at=datetime.now(UTC),
            ),
        )
        chain.append(bogus_accept)
        assert compute_lifecycle_state(chain) == LifecycleState.PENDING

    def test_acceptance_mismatched_signatory_did_ignored(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """ACCEPTANCE whose signatory_did != author_id must not count."""
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)

        bogus_accept = synpareia.create_block(
            profile_b,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=chain.id,
                policy_hash=policy_hash(policy),
                signatory_did=profile.id,  # claims to accept for proposer
                accepted_at=datetime.now(UTC),
            ),
        )
        chain.append(bogus_accept)
        assert compute_lifecycle_state(chain) == LifecycleState.PENDING
