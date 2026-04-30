"""Tests for anchors: creation, verification, traversal."""

from __future__ import annotations

import synpareia
from synpareia.anchor import AnchorPayload, create_anchor_block
from synpareia.anchor.traversal import find_anchors, resolve_anchor, trace_correspondence
from synpareia.anchor.verify import verify_anchor, verify_anchor_from_block
from synpareia.policy import Policy, templates
from synpareia.types import AnchorType, BlockType


class TestCreateAnchorBlock:
    def test_creates_anchor(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile, cop_policy: Policy
    ) -> None:
        source = synpareia.create_chain(profile, policy=cop_policy)
        target_policy = templates.sphere(profile, profile_b)
        target = synpareia.create_chain(profile, policy=target_policy)

        block = synpareia.create_block(profile, BlockType.MESSAGE, "target msg")
        target_pos = target.append(block)

        anchor_block, pos = create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=block.content_hash,
        )

        assert anchor_block.type == BlockType.ANCHOR
        assert pos.sequence == source.length
        assert "anchor" in anchor_block.metadata


class TestVerifyAnchor:
    def test_valid_anchor(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile, cop_policy: Policy
    ) -> None:
        source = synpareia.create_chain(profile, policy=cop_policy)
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        block = synpareia.create_block(profile, BlockType.MESSAGE, "msg")
        target_pos = target.append(block)

        anchor_block, _ = create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=block.content_hash,
        )

        valid, err = verify_anchor(anchor_block, target)
        assert valid, err

    def test_wrong_target_chain(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile, cop_policy: Policy
    ) -> None:
        source = synpareia.create_chain(profile, policy=cop_policy)
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))
        other = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        block = synpareia.create_block(profile, BlockType.MESSAGE, "msg")
        target_pos = target.append(block)

        anchor_block, _ = create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=block.content_hash,
        )

        valid, err = verify_anchor(anchor_block, other)
        assert not valid
        assert "targets chain" in err

    def test_wrong_content_hash(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile, cop_policy: Policy
    ) -> None:
        source = synpareia.create_chain(profile, policy=cop_policy)
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        block = synpareia.create_block(profile, BlockType.MESSAGE, "msg")
        target_pos = target.append(block)

        anchor_block, _ = create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=b"\x00" * 32,
        )

        valid, err = verify_anchor(anchor_block, target)
        assert not valid
        assert "content_hash" in err


class TestVerifyAnchorFromBlock:
    def test_valid(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile, cop_policy: Policy
    ) -> None:
        source = synpareia.create_chain(profile, policy=cop_policy)
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        block = synpareia.create_block(profile, BlockType.MESSAGE, "msg")
        target_pos = target.append(block)

        anchor_block, _ = create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=block.content_hash,
        )

        valid, err = verify_anchor_from_block(anchor_block, block, target_pos.sequence)
        assert valid, err

    def test_wrong_sequence(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile, cop_policy: Policy
    ) -> None:
        source = synpareia.create_chain(profile, policy=cop_policy)
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        block = synpareia.create_block(profile, BlockType.MESSAGE, "msg")
        target_pos = target.append(block)

        anchor_block, _ = create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=block.content_hash,
        )

        valid, _ = verify_anchor_from_block(anchor_block, block, 999)
        assert not valid


class TestFindAnchors:
    def test_finds_anchors(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile, cop_policy: Policy
    ) -> None:
        source = synpareia.create_chain(profile, policy=cop_policy)
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        block = synpareia.create_block(profile, BlockType.MESSAGE, "msg")
        target_pos = target.append(block)

        create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=block.content_hash,
        )

        source.append(synpareia.create_block(profile, BlockType.MESSAGE, "normal"))

        anchors = find_anchors(source)
        assert len(anchors) == 1
        _, payload = anchors[0]
        assert payload.target_chain_id == target.id

    def test_filter_by_anchor_type(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile, cop_policy: Policy
    ) -> None:
        source = synpareia.create_chain(profile, policy=cop_policy)
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        block = synpareia.create_block(profile, BlockType.MESSAGE, "msg")
        target_pos = target.append(block)

        create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=block.content_hash,
            anchor_type=AnchorType.CORRESPONDENCE,
        )
        create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=block.content_hash,
            anchor_type=AnchorType.RECEIPT,
        )

        corr = find_anchors(source, anchor_type=str(AnchorType.CORRESPONDENCE))
        assert len(corr) == 1
        receipts = find_anchors(source, anchor_type=str(AnchorType.RECEIPT))
        assert len(receipts) == 1


class TestResolveAnchor:
    def test_resolves(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile, cop_policy: Policy
    ) -> None:
        source = synpareia.create_chain(profile, policy=cop_policy)
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        block = synpareia.create_block(profile, BlockType.MESSAGE, "msg")
        target_pos = target.append(block)

        create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=block.content_hash,
        )

        anchors = find_anchors(source)
        _, payload = anchors[0]

        resolved = resolve_anchor(payload, {target.id: target})
        assert resolved is not None
        assert resolved.content == block.content

    def test_missing_chain(self, profile: synpareia.Profile) -> None:
        payload = AnchorPayload(
            target_chain_id="nonexistent",
            target_sequence=1,
            target_block_hash=b"\x00" * 32,
            anchor_type=AnchorType.CORRESPONDENCE,
        )
        assert resolve_anchor(payload, {}) is None


class TestTraceCorrespondence:
    def test_trace(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile, cop_policy: Policy
    ) -> None:
        cop = synpareia.create_chain(profile, policy=cop_policy)
        sphere = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        msg = synpareia.create_block(profile, BlockType.MESSAGE, "hello")
        sphere_pos = sphere.append(msg)
        cop.append(msg)

        create_anchor_block(
            profile,
            cop,
            target_chain_id=sphere.id,
            target_sequence=sphere_pos.sequence,
            target_block_hash=msg.content_hash,
            anchor_type=AnchorType.CORRESPONDENCE,
        )

        pairs = trace_correspondence(cop, sphere)
        assert len(pairs) == 1
        _, tgt_pos = pairs[0]
        assert tgt_pos.sequence == sphere_pos.sequence
