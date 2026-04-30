"""Tests for the policy template factories."""

from __future__ import annotations

import pytest

import synpareia
from synpareia.policy import Policy, templates
from synpareia.types import BlockType, ChainType


class TestCopTemplate:
    def test_single_signatory(self, profile: synpareia.Profile) -> None:
        policy = templates.cop(profile)
        assert policy.chain_type == str(ChainType.COP)
        assert policy.signatory_dids == (profile.id,)
        assert policy.signatories[0].role == "owner"

    def test_permits_thought_and_commitment(self, profile: synpareia.Profile) -> None:
        """CoP must permit the private-workshop block types."""
        policy = templates.cop(profile)
        assert str(BlockType.THOUGHT) in policy.block_types_permitted
        assert str(BlockType.COMMITMENT) in policy.block_types_permitted
        assert str(BlockType.POLICY) in policy.block_types_permitted

    def test_override_fork_permitted(self, profile: synpareia.Profile) -> None:
        policy = templates.cop(profile, fork_permitted=True)
        assert policy.fork_permitted is True

    def test_override_preserves_signatories(self, profile: synpareia.Profile) -> None:
        """Overrides should not replace signatories by mistake."""
        policy = templates.cop(profile, termination_rule="conclusion_is_absolute")
        assert policy.signatory_dids == (profile.id,)
        assert policy.termination_rule == "conclusion_is_absolute"


class TestSphereTemplate:
    def test_two_party_roles(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        assert policy.chain_type == str(ChainType.SPHERE)
        roles = {s.role for s in policy.signatories}
        assert roles == {"owner", "counterparty"}

    def test_multi_party_roles(
        self,
        profile: synpareia.Profile,
        profile_b: synpareia.Profile,
    ) -> None:
        profile_c = synpareia.generate()
        profile_d = synpareia.generate()
        policy = templates.sphere(profile, profile_b, profile_c, profile_d)
        roles = [s.role for s in policy.signatories]
        assert roles[0] == "owner"
        assert roles[1:] == ["participant_1", "participant_2", "participant_3"]

    def test_requires_two_signatories(self, profile: synpareia.Profile) -> None:
        with pytest.raises(ValueError, match="at least two"):
            templates.sphere(profile)

    def test_witness_declared(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        witness = synpareia.generate()
        policy = templates.sphere(profile, profile_b, witness=witness)
        assert policy.witness_dids == (witness.id,)
        assert "timestamp" in policy.witnesses[0].roles

    def test_no_witness_by_default(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        assert policy.witnesses == ()

    def test_message_rule_requires_receipt(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        msg_rules = [r for r in policy.per_block_rules if r.block_type == str(BlockType.MESSAGE)]
        assert msg_rules
        assert all(r.receipt_required for r in msg_rules)

    def test_permitted_types_for_sphere(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        assert str(BlockType.JOIN) in policy.block_types_permitted
        assert str(BlockType.LEAVE) in policy.block_types_permitted
        # Sphere does not permit THOUGHT — that's a private CoP type.
        assert str(BlockType.THOUGHT) not in policy.block_types_permitted


class TestAuditTemplate:
    def test_participants_as_signatories(self, profile: synpareia.Profile) -> None:
        policy = templates.audit(profile)
        assert policy.chain_type == str(ChainType.AUDIT)
        assert policy.signatory_dids == (profile.id,)
        assert all(s.role == "participant" for s in policy.signatories)

    def test_auditors_become_witnesses(self, profile: synpareia.Profile) -> None:
        auditor = synpareia.generate()
        policy = templates.audit(profile, auditors=(auditor,))
        assert policy.witness_dids == (auditor.id,)
        assert "arbitrate" in policy.witnesses[0].roles

    def test_requires_at_least_one_participant(self) -> None:
        with pytest.raises(ValueError, match="at least one participant"):
            templates.audit()

    def test_termination_is_absolute(self, profile: synpareia.Profile) -> None:
        policy = templates.audit(profile)
        assert policy.termination_rule == "conclusion_is_absolute"


class TestCustomTemplate:
    def test_requires_core_fields(self) -> None:
        with pytest.raises(ValueError, match="missing required"):
            templates.custom(version="1")

    def test_builds_with_minimum_fields(self, profile: synpareia.Profile) -> None:
        policy = templates.custom(
            version="1",
            chain_type="custom",
            signatories=(),
            block_types_permitted=(str(BlockType.POLICY),),
        )
        assert isinstance(policy, Policy)
        assert policy.chain_type == "custom"
        # The default amendment rules are applied automatically.
        assert policy.amendment_rules.default == "all_signatories_cosign"


class TestDefaultAmendments:
    """All templates should ship the same default amendment rule set."""

    def test_cop_signatories_add_rule(self, profile: synpareia.Profile) -> None:
        policy = templates.cop(profile)
        assert (
            policy.amendment_rules.requirement_for("signatories.add")
            == "all_signatories_cosign+new_signatory_accepts"
        )

    def test_sphere_retention_lengthen_rule(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        assert (
            policy.amendment_rules.requirement_for("retention_days.lengthen")
            == "all_signatories_cosign+affected_witnesses_acknowledge"
        )

    def test_catch_all_default(self, profile: synpareia.Profile) -> None:
        policy = templates.cop(profile)
        assert policy.amendment_rules.requirement_for("unlisted.path") == "all_signatories_cosign"
