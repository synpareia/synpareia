"""Tests for the policy model, serialization, and builder."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

import synpareia
from synpareia.policy import (
    AmendmentOverride,
    AmendmentRules,
    GdprMetadata,
    PerBlockRule,
    PolicyBuilder,
    Retention,
    RetractorRule,
    RevealerRule,
    Signatory,
    WitnessDecl,
    acceptance_bytes,
    acceptance_payload,
    ack_bytes,
    ack_payload,
    conclusion_bytes,
    conclusion_payload,
    policy_canonical_bytes,
    policy_from_dict,
    policy_hash,
    policy_to_dict,
    templates,
)
from synpareia.types import BlockType, ChainType


class TestPolicyModel:
    def test_is_frozen(self, profile: synpareia.Profile) -> None:
        policy = templates.cop(profile)
        with pytest.raises((AttributeError, TypeError)):
            policy.chain_type = "mutated"  # type: ignore[misc]

    def test_is_hashable(self, profile: synpareia.Profile) -> None:
        policy = templates.cop(profile)
        # Frozen dataclasses of hashables must be hashable themselves.
        assert isinstance(hash(policy), int)

    def test_signatory_dids(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        assert set(policy.signatory_dids) == {profile.id, profile_b.id}
        assert policy.is_signatory(profile.id)
        assert policy.is_signatory(profile_b.id)
        assert not policy.is_signatory("did:synpareia:not-a-party")

    def test_witness_dids(
        self,
        profile: synpareia.Profile,
        profile_b: synpareia.Profile,
    ) -> None:
        witness = synpareia.generate()
        policy = templates.sphere(profile, profile_b, witness=witness)
        assert witness.id in policy.witness_dids
        assert policy.is_witness(witness.id)
        assert not policy.is_witness(profile.id)


class TestAmendmentRules:
    def test_override_wins_over_default(self) -> None:
        rules = AmendmentRules(
            default="all_signatories_cosign",
            overrides=(AmendmentOverride(path="signatories.add", requirement="owner_decides"),),
        )
        assert rules.requirement_for("signatories.add") == "owner_decides"
        assert rules.requirement_for("some.other.path") == "all_signatories_cosign"

    def test_default_applies_when_no_override(self) -> None:
        rules = AmendmentRules(default="quorum")
        assert rules.requirement_for("anything") == "quorum"


class TestSerializationRoundTrip:
    def test_cop_round_trip(self, profile: synpareia.Profile) -> None:
        original = templates.cop(profile)
        data = policy_to_dict(original)
        restored = policy_from_dict(data)
        assert restored == original

    def test_sphere_round_trip(
        self,
        profile: synpareia.Profile,
        profile_b: synpareia.Profile,
    ) -> None:
        witness = synpareia.generate()
        original = templates.sphere(profile, profile_b, witness=witness)
        data = policy_to_dict(original)
        restored = policy_from_dict(data)
        assert restored == original

    def test_gdpr_round_trip(self, profile: synpareia.Profile) -> None:
        original = templates.cop(
            profile,
            gdpr=GdprMetadata(
                controller_did=profile.id,
                purpose="research",
                lawful_basis="consent",
                retention_days=90,
                subject_rights_contact="dpo@example.com",
            ),
        )
        data = policy_to_dict(original)
        restored = policy_from_dict(data)
        assert restored == original
        assert restored.gdpr is not None
        assert restored.gdpr.controller_did == profile.id


class TestCanonicalBytes:
    def test_bytes_are_deterministic(self, profile: synpareia.Profile) -> None:
        a = policy_canonical_bytes(templates.cop(profile))
        b = policy_canonical_bytes(templates.cop(profile))
        assert a == b

    def test_bytes_are_valid_json(self, profile: synpareia.Profile) -> None:
        """JCS output must be json.loads-compatible (JCS is a JSON subset)."""
        raw = policy_canonical_bytes(templates.cop(profile))
        parsed = json.loads(raw.decode())
        assert parsed["chain_type"] == str(ChainType.COP)

    def test_hash_equals_sha256_of_canonical_bytes(self, profile: synpareia.Profile) -> None:
        import hashlib

        policy = templates.cop(profile)
        expected = hashlib.sha256(policy_canonical_bytes(policy)).digest()
        assert policy_hash(policy) == expected

    def test_different_policies_hash_differently(
        self,
        profile: synpareia.Profile,
        profile_b: synpareia.Profile,
    ) -> None:
        a = policy_hash(templates.cop(profile))
        b = policy_hash(templates.cop(profile_b))
        assert a != b

    def test_chain_policy_hash_matches_genesis_content_hash(
        self, profile: synpareia.Profile
    ) -> None:
        """The chain's declared policy_hash must equal the POLICY block's content_hash."""
        policy = templates.cop(profile)
        chain = synpareia.create_chain(profile, policy=policy)
        genesis = chain.get_block(1)
        assert genesis is not None
        assert str(genesis.type) == str(BlockType.POLICY)
        assert chain.policy_hash == genesis.content_hash
        assert chain.policy_hash == policy_hash(policy)


class TestEnvelopePayloads:
    CID = "ch_test_12345"

    def test_acceptance_payload_shape(self, profile: synpareia.Profile) -> None:
        ph = policy_hash(templates.cop(profile))
        ts = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
        payload = acceptance_payload(
            chain_id=self.CID, policy_hash=ph, signatory_did=profile.id, accepted_at=ts
        )
        assert payload["kind"] == "acceptance"
        assert payload["chain_id"] == self.CID
        assert payload["policy_hash"] == ph.hex()
        assert payload["signatory_did"] == profile.id
        assert payload["accepted_at"] == ts.isoformat()

    def test_acceptance_bytes_are_canonical(self, profile: synpareia.Profile) -> None:
        ph = policy_hash(templates.cop(profile))
        ts = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
        a = acceptance_bytes(
            chain_id=self.CID, policy_hash=ph, signatory_did=profile.id, accepted_at=ts
        )
        b = acceptance_bytes(
            chain_id=self.CID, policy_hash=ph, signatory_did=profile.id, accepted_at=ts
        )
        assert a == b
        # JCS output parses back
        assert json.loads(a.decode())["kind"] == "acceptance"

    def test_ack_payload_shape(self, profile: synpareia.Profile) -> None:
        ph = policy_hash(templates.cop(profile))
        ts = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
        payload = ack_payload(
            chain_id=self.CID, policy_hash=ph, witness_did=profile.id, acked_at=ts
        )
        assert payload["kind"] == "ack"
        assert payload["chain_id"] == self.CID
        assert payload["witness_did"] == profile.id

    def test_ack_bytes_deterministic(self, profile: synpareia.Profile) -> None:
        ph = policy_hash(templates.cop(profile))
        ts = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
        assert ack_bytes(
            chain_id=self.CID, policy_hash=ph, witness_did=profile.id, acked_at=ts
        ) == ack_bytes(chain_id=self.CID, policy_hash=ph, witness_did=profile.id, acked_at=ts)

    def test_conclusion_payload_with_reason(self, profile: synpareia.Profile) -> None:
        ts = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
        payload = conclusion_payload(
            chain_id=self.CID,
            author_did=profile.id,
            concluded_at=ts,
            reason="work complete",
        )
        assert payload["kind"] == "conclusion"
        assert payload["chain_id"] == self.CID
        assert payload["reason"] == "work complete"

    def test_conclusion_payload_without_reason(self, profile: synpareia.Profile) -> None:
        ts = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
        payload = conclusion_payload(chain_id=self.CID, author_did=profile.id, concluded_at=ts)
        assert "reason" not in payload

    def test_conclusion_bytes_deterministic(self, profile: synpareia.Profile) -> None:
        ts = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
        a = conclusion_bytes(chain_id=self.CID, author_did=profile.id, concluded_at=ts)
        b = conclusion_bytes(chain_id=self.CID, author_did=profile.id, concluded_at=ts)
        assert a == b


class TestPolicyBuilder:
    def test_minimal_build(self, profile: synpareia.Profile) -> None:
        policy = (
            PolicyBuilder(ChainType.COP)
            .signatory(profile.id, "owner")
            .allow_block_type(str(BlockType.POLICY))
            .allow_block_type(str(BlockType.MESSAGE))
            .build()
        )
        assert policy.chain_type == str(ChainType.COP)
        assert policy.signatory_dids == (profile.id,)
        assert str(BlockType.MESSAGE) in policy.block_types_permitted

    def test_fluent_rule_adds_to_permitted(self, profile: synpareia.Profile) -> None:
        policy = (
            PolicyBuilder(ChainType.COP)
            .signatory(profile.id, "owner")
            .rule(
                str(BlockType.MESSAGE),
                authors=("signatory:owner",),
                retention=Retention(mode="indefinite"),
            )
            .build()
        )
        assert str(BlockType.MESSAGE) in policy.block_types_permitted
        assert any(rule.block_type == str(BlockType.MESSAGE) for rule in policy.per_block_rules)

    def test_witness_added(self, profile: synpareia.Profile) -> None:
        witness = synpareia.generate()
        policy = (
            PolicyBuilder(ChainType.SPHERE)
            .signatory(profile.id, "owner")
            .witness(witness.id, roles=("timestamp",), retention_days=365)
            .build()
        )
        assert policy.witnesses[0].did == witness.id
        assert policy.witnesses[0].retention_days == 365

    def test_amendment_rule_override(self, profile: synpareia.Profile) -> None:
        policy = (
            PolicyBuilder(ChainType.COP)
            .signatory(profile.id, "owner")
            .amendment_default("quorum")
            .amendment_rule("signatories.add", "owner_decides")
            .build()
        )
        assert policy.amendment_rules.default == "quorum"
        assert policy.amendment_rules.requirement_for("signatories.add") == "owner_decides"

    def test_revealers_and_retractors(self, profile: synpareia.Profile) -> None:
        policy = (
            PolicyBuilder(ChainType.COP)
            .signatory(profile.id, "owner")
            .revealers(str(BlockType.THOUGHT), allowed=("author_only",))
            .retractors(str(BlockType.MESSAGE), allowed=("author_only",))
            .build()
        )
        assert policy.allowed_revealers == (
            RevealerRule(block_type=str(BlockType.THOUGHT), allowed=("author_only",)),
        )
        assert policy.allowed_retractors == (
            RetractorRule(block_type=str(BlockType.MESSAGE), allowed=("author_only",)),
        )


class TestDataclassInvariants:
    """Small smoke checks on the leaf records themselves."""

    def test_signatory_equality(self) -> None:
        assert Signatory("did:x", "owner") == Signatory("did:x", "owner")
        assert Signatory("did:x", "owner") != Signatory("did:x", "counterparty")

    def test_per_block_rule_defaults(self) -> None:
        rule = PerBlockRule(block_type="message")
        assert rule.signature_required is True
        assert rule.receipt_required is False
        assert rule.retention is None

    def test_witness_decl_defaults(self) -> None:
        w = WitnessDecl(did="did:w")
        assert w.roles == ()
        assert w.retention_days is None

    def test_retention_requires_mode(self) -> None:
        assert Retention(mode="indefinite").duration_days is None
        assert Retention(mode="bounded", duration_days=30).duration_days == 30
