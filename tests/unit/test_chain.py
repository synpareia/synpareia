"""Tests for Chain: creation, append, verification, querying.

Under v0.3 every chain has a POLICY block at position 1. Tests compute
MESSAGE-block positions as `policy_offset + n` where policy_offset = 1.
"""

from __future__ import annotations

import synpareia
from synpareia.chain.position import compute_position_hash
from synpareia.policy import Policy, templates
from synpareia.types import BlockType, ChainType, LifecycleState

POLICY_OFFSET = 1


class TestCreateChain:
    def test_creates_chain_with_genesis_policy(
        self, profile: synpareia.Profile, cop_policy: Policy
    ) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        assert chain.id.startswith("chn_")
        assert chain.owner_id == profile.id
        assert chain.chain_type == str(ChainType.COP)
        assert chain.head_hash is not None
        assert chain.length == 1
        assert chain.policy_hash is not None
        assert chain.state == LifecycleState.ACTIVE

    def test_custom_chain_type(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)
        assert chain.chain_type == str(ChainType.SPHERE)

    def test_with_metadata(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy, metadata={"purpose": "test"})
        assert chain.metadata == {"purpose": "test"}

    def test_sphere_chain_starts_pending(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        policy = templates.sphere(profile, profile_b)
        chain = synpareia.create_chain(profile, policy=policy)
        assert chain.state == LifecycleState.PENDING


class TestAppend:
    def test_first_append(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        block = synpareia.create_block(profile, BlockType.MESSAGE, "hello")
        pos = chain.append(block)
        assert pos.sequence == POLICY_OFFSET + 1
        assert pos.parent_hash is not None  # genesis block is parent
        assert chain.length == POLICY_OFFSET + 1
        assert chain.head_hash == pos.position_hash

    def test_second_append(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        b1 = synpareia.create_block(profile, BlockType.MESSAGE, "first")
        b2 = synpareia.create_block(profile, BlockType.MESSAGE, "second")
        p1 = chain.append(b1)
        p2 = chain.append(b2)
        assert p2.sequence == p1.sequence + 1
        assert p2.parent_hash == p1.position_hash
        assert chain.length == POLICY_OFFSET + 2
        assert chain.head_hash == p2.position_hash

    def test_position_hash_formula(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        genesis_head = chain.head_hash
        block = synpareia.create_block(profile, BlockType.MESSAGE, "test")
        pos = chain.append(block)

        expected = compute_position_hash(
            sequence=pos.sequence,
            author_id=block.author_id,
            block_type=str(block.type),
            created_at=block.created_at,
            content_hash=block.content_hash,
            parent_hash=genesis_head,
        )
        assert pos.position_hash == expected

    def test_head_tracking(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        head = chain.head
        assert head is not None
        assert head.sequence == 1  # POLICY block

        b1 = synpareia.create_block(profile, BlockType.MESSAGE, "a")
        chain.append(b1)
        head = chain.head
        assert head is not None
        assert head.sequence == 2

        b2 = synpareia.create_block(profile, BlockType.MESSAGE, "b")
        chain.append(b2)
        assert chain.head.sequence == 3


class TestVerify:
    def test_genesis_only_chain(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        valid, errors = chain.verify(public_keys={profile.id: profile.public_key})
        assert valid
        assert errors == []

    def test_valid_chain(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        for i in range(5):
            block = synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}")
            chain.append(block)
        valid, errors = chain.verify(public_keys={profile.id: profile.public_key})
        assert valid
        assert errors == []

    def test_tampered_position_hash(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        block = synpareia.create_block(profile, BlockType.MESSAGE, "test")
        pos = chain.append(block)

        from synpareia.chain import ChainPosition

        tampered = ChainPosition(
            chain_id=pos.chain_id,
            sequence=pos.sequence,
            block_id=pos.block_id,
            parent_hash=pos.parent_hash,
            position_hash=b"\x00" * 32,
        )
        chain._store._positions[(chain.id, pos.sequence)] = tampered
        chain.head_hash = tampered.position_hash

        valid, errors = chain.verify()
        assert not valid
        assert any("position_hash" in e for e in errors)


class TestQuery:
    def test_query_by_type(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "msg"))
        chain.append(synpareia.create_block(profile, BlockType.THOUGHT, "thought"))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "msg2"))

        results = chain.query(block_type=str(BlockType.MESSAGE))
        assert len(results) == 2

    def test_query_by_author(
        self,
        profile: synpareia.Profile,
        profile_b: synpareia.Profile,
        cop_policy: Policy,
    ) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "a"))
        chain.append(synpareia.create_block(profile_b, BlockType.MESSAGE, "b"))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "c"))

        results = chain.query(author_id=profile_b.id)
        assert len(results) == 1
        _, block = results[0]
        assert block.author_id == profile_b.id

    def test_query_with_limit(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        for i in range(10):
            chain.append(synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}"))
        results = chain.query(block_type=str(BlockType.MESSAGE), limit=3)
        assert len(results) == 3


class TestGetMethods:
    def test_get_position(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        block = synpareia.create_block(profile, BlockType.MESSAGE, "test")
        pos = chain.append(block)
        fetched = chain.get_position(pos.sequence)
        assert fetched == pos

    def test_get_position_missing(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        assert chain.get_position(999) is None

    def test_get_block(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        block = synpareia.create_block(profile, BlockType.MESSAGE, "test")
        chain.append(block)
        fetched = chain.get_block(2)
        assert fetched is not None
        assert fetched.id == block.id

    def test_get_positions_range(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        for i in range(5):
            chain.append(synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}"))
        # Positions: 1=POLICY, 2..6=messages
        positions = chain.get_positions(3, 5)
        assert len(positions) == 3
        assert [p.sequence for p in positions] == [3, 4, 5]
