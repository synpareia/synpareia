"""Tests for KEY_ROTATION blocks (Phase 0.2 of the funnel-implementation-roadmap).

Coverage:
- ``create_key_rotation_block`` round-trips with the new key signing
  subsequent activity.
- ``parse_key_rotation_payload`` rejects malformed payloads (bad JSON,
  wrong kind, malformed base64, wrong key length, non-ISO timestamps).
- ``verify_key_rotation_block`` rejects mismatched old keys, wrong
  block type, no-op rotations, missing signatures.
- ``resolve_did_key`` walks single and multi-step rotation chains and
  fails closed when any step breaks.
- Key-loss recovery scenario: without the old private key, no valid
  KEY_ROTATION block can be minted, so ``resolve_did_key`` cannot
  catch up — confirms key-loss is terminal under v1 semantics.
"""

from __future__ import annotations

import base64
import json

import pytest

import synpareia
from synpareia import (
    Block,
    KeyRotationPayload,
    create_key_rotation_block,
    parse_key_rotation_payload,
    resolve_did_key,
    verify_key_rotation_block,
)
from synpareia.chain.operations import append_block, create_chain
from synpareia.types import BlockType

# ---------------------------------------------------------------------------
# create_key_rotation_block
# ---------------------------------------------------------------------------


class TestCreateKeyRotationBlock:
    def test_round_trip(self, profile: synpareia.Profile) -> None:
        new_key = synpareia.generate().public_key
        block = create_key_rotation_block(profile, new_public_key=new_key)
        assert str(block.type) == str(BlockType.KEY_ROTATION)
        assert block.author_id == profile.id
        assert block.signature is not None
        payload = parse_key_rotation_payload(block)
        assert payload is not None
        assert payload.did == profile.id
        assert payload.old_key == profile.public_key
        assert payload.new_key == new_key

    def test_rejects_missing_private_key(self) -> None:
        # Construct a public-only profile (no private key)
        signer = synpareia.generate()
        public_only = synpareia.from_public_key(signer.public_key)
        with pytest.raises(ValueError, match="profile must hold the current private key"):
            create_key_rotation_block(public_only, new_public_key=b"\x00" * 32)

    def test_rejects_wrong_length_new_key(self, profile: synpareia.Profile) -> None:
        with pytest.raises(ValueError, match="new_public_key must be 32 bytes"):
            create_key_rotation_block(profile, new_public_key=b"\x00" * 16)

    def test_rejects_no_op_rotation(self, profile: synpareia.Profile) -> None:
        with pytest.raises(ValueError, match="identical to old_public_key"):
            create_key_rotation_block(profile, new_public_key=profile.public_key)


# ---------------------------------------------------------------------------
# parse_key_rotation_payload
# ---------------------------------------------------------------------------


class TestParseKeyRotationPayload:
    def test_returns_none_for_wrong_block_type(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(profile, BlockType.MESSAGE, "hi")
        assert parse_key_rotation_payload(block) is None

    def test_returns_none_for_missing_content(self, profile: synpareia.Profile) -> None:
        block = Block(
            id="blk_x",
            type=BlockType.KEY_ROTATION,
            author_id=profile.id,
            content_hash=b"\x00" * 32,
            created_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
            content=None,
        )
        assert parse_key_rotation_payload(block) is None

    def test_returns_none_for_invalid_json(self, profile: synpareia.Profile) -> None:
        block = _block_with_content(profile, b"not json at all")
        assert parse_key_rotation_payload(block) is None

    def test_returns_none_for_wrong_kind(self, profile: synpareia.Profile) -> None:
        bad = json.dumps(
            {
                "kind": "something_else",
                "did": profile.id,
                "old_key_b64": base64.b64encode(b"\x00" * 32).decode(),
                "new_key_b64": base64.b64encode(b"\x01" * 32).decode(),
                "rotated_at": "2026-05-05T00:00:00+00:00",
            }
        ).encode()
        assert parse_key_rotation_payload(_block_with_content(profile, bad)) is None

    def test_returns_none_for_malformed_base64(self, profile: synpareia.Profile) -> None:
        bad = json.dumps(
            {
                "kind": "key_rotation",
                "did": profile.id,
                "old_key_b64": "not-valid-base64!!!",
                "new_key_b64": base64.b64encode(b"\x01" * 32).decode(),
                "rotated_at": "2026-05-05T00:00:00+00:00",
            }
        ).encode()
        assert parse_key_rotation_payload(_block_with_content(profile, bad)) is None

    def test_returns_none_for_wrong_key_length(self, profile: synpareia.Profile) -> None:
        bad = json.dumps(
            {
                "kind": "key_rotation",
                "did": profile.id,
                "old_key_b64": base64.b64encode(b"\x00" * 16).decode(),  # 16, not 32
                "new_key_b64": base64.b64encode(b"\x01" * 32).decode(),
                "rotated_at": "2026-05-05T00:00:00+00:00",
            }
        ).encode()
        assert parse_key_rotation_payload(_block_with_content(profile, bad)) is None

    def test_returns_none_for_unparseable_timestamp(self, profile: synpareia.Profile) -> None:
        bad = json.dumps(
            {
                "kind": "key_rotation",
                "did": profile.id,
                "old_key_b64": base64.b64encode(b"\x00" * 32).decode(),
                "new_key_b64": base64.b64encode(b"\x01" * 32).decode(),
                "rotated_at": "not a date",
            }
        ).encode()
        assert parse_key_rotation_payload(_block_with_content(profile, bad)) is None


# ---------------------------------------------------------------------------
# verify_key_rotation_block
# ---------------------------------------------------------------------------


class TestVerifyKeyRotationBlock:
    def test_valid_block_passes(self, profile: synpareia.Profile) -> None:
        new_key = synpareia.generate().public_key
        block = create_key_rotation_block(profile, new_public_key=new_key)
        valid, errors = verify_key_rotation_block(block, expected_old_key=profile.public_key)
        assert valid, errors

    def test_rejects_wrong_block_type(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(profile, BlockType.MESSAGE, "hi")
        valid, errors = verify_key_rotation_block(block, expected_old_key=profile.public_key)
        assert not valid
        assert any("expected 'key_rotation'" in e for e in errors)

    def test_rejects_old_key_mismatch(self, profile: synpareia.Profile) -> None:
        new_key = synpareia.generate().public_key
        block = create_key_rotation_block(profile, new_public_key=new_key)
        wrong_key = synpareia.generate().public_key
        valid, errors = verify_key_rotation_block(block, expected_old_key=wrong_key)
        assert not valid
        assert any("does not match the expected current controlling key" in e for e in errors)

    def test_rejects_missing_signature(self, profile: synpareia.Profile) -> None:
        new_key = synpareia.generate().public_key
        block = create_key_rotation_block(profile, new_public_key=new_key)
        unsigned = Block(
            id=block.id,
            type=block.type,
            author_id=block.author_id,
            content_hash=block.content_hash,
            created_at=block.created_at,
            content=block.content,
            signature=None,
            metadata=block.metadata,
            co_signatures=block.co_signatures,
        )
        valid, errors = verify_key_rotation_block(unsigned, expected_old_key=profile.public_key)
        assert not valid
        assert any("must be signed" in e for e in errors)

    def test_rejects_tampered_payload(self, profile: synpareia.Profile) -> None:
        """A block whose payload was rewritten after signing fails — the
        signature is over the envelope (which binds content_hash), so a
        content swap breaks verification."""
        new_key = synpareia.generate().public_key
        block = create_key_rotation_block(profile, new_public_key=new_key)

        # Replace the new_key in the payload but keep the signature
        tampered_payload = json.dumps(
            {
                "kind": "key_rotation",
                "did": profile.id,
                "old_key_b64": base64.b64encode(profile.public_key).decode(),
                "new_key_b64": base64.b64encode(b"\x99" * 32).decode(),
                "rotated_at": "2026-05-05T00:00:00+00:00",
            }
        ).encode()
        tampered = Block(
            id=block.id,
            type=block.type,
            author_id=block.author_id,
            content_hash=block.content_hash,  # stays the original — content_hash mismatch
            created_at=block.created_at,
            content=tampered_payload,
            signature=block.signature,
            metadata=block.metadata,
            co_signatures=block.co_signatures,
        )
        valid, errors = verify_key_rotation_block(tampered, expected_old_key=profile.public_key)
        assert not valid
        # Either the content_hash check or the signature check fails — both
        # surface via verify_block returning False
        assert any("signature does not verify" in e for e in errors)


# ---------------------------------------------------------------------------
# resolve_did_key (chain walking)
# ---------------------------------------------------------------------------


class TestResolveDidKey:
    def test_no_rotations_returns_initial_key(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        # Sphere chain between two profiles, no rotations
        from synpareia.policy import templates

        chain = create_chain(profile, policy=templates.sphere(profile, profile_b))
        resolved = resolve_did_key(chain, profile.id, initial_key=profile.public_key)
        assert resolved == profile.public_key

    def test_single_rotation(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        from synpareia.policy import templates

        chain = create_chain(profile, policy=templates.sphere(profile, profile_b))
        new_key_profile = synpareia.generate()
        rotation = create_key_rotation_block(profile, new_public_key=new_key_profile.public_key)
        append_block(chain, rotation)

        resolved = resolve_did_key(chain, profile.id, initial_key=profile.public_key)
        assert resolved == new_key_profile.public_key

    def test_multi_step_rotation(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """A chain can carry several rotations; each one applies in sequence."""
        from synpareia.policy import templates

        chain = create_chain(profile, policy=templates.sphere(profile, profile_b))

        # First rotation: original → key_2
        key2 = synpareia.generate()
        rot1 = create_key_rotation_block(profile, new_public_key=key2.public_key)
        append_block(chain, rot1)

        # Second rotation: must be signed with the key_2 private key.
        # Construct a profile that holds key_2's private + claims the
        # original DID (since the DID is permanent, derived from the
        # original public key).
        profile_at_key2 = synpareia.Profile(
            id=profile.id,
            public_key=key2.public_key,
            private_key=key2.private_key,
        )
        key3 = synpareia.generate()
        rot2 = create_key_rotation_block(profile_at_key2, new_public_key=key3.public_key)
        append_block(chain, rot2)

        resolved = resolve_did_key(chain, profile.id, initial_key=profile.public_key)
        assert resolved == key3.public_key

    def test_returns_none_when_rotation_signed_by_wrong_key(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """A rotation block whose old-key signature doesn't match the
        running expected key invalidates the chain — ``resolve_did_key``
        returns ``None``."""
        from synpareia.policy import templates

        chain = create_chain(profile, policy=templates.sphere(profile, profile_b))

        # Forge a rotation: a different profile (impersonating the DID)
        # creates a block claiming to rotate the original DID's key. The
        # signature is over the wrong private key.
        impostor = synpareia.generate()
        forged_profile = synpareia.Profile(
            id=profile.id,  # claims original DID
            public_key=impostor.public_key,
            private_key=impostor.private_key,
        )
        new_key = synpareia.generate().public_key
        # The block will be signed with impostor's key but ``profile.id``
        # doesn't match impostor.public_key. We need to construct it
        # manually so the payload claims the wrong old_key.
        forged = create_key_rotation_block(forged_profile, new_public_key=new_key)
        append_block(chain, forged)

        # Walking from the genuine initial_key (profile.public_key) finds
        # the forged block asserts old_key=impostor.public_key, which
        # doesn't match profile.public_key → break, return None.
        resolved = resolve_did_key(chain, profile.id, initial_key=profile.public_key)
        assert resolved is None

    def test_ignores_rotations_for_other_dids(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """Rotations authored by other DIDs don't affect ``did``'s key."""
        from synpareia.policy import templates

        chain = create_chain(profile, policy=templates.sphere(profile, profile_b))

        # profile_b rotates their own key
        b_new = synpareia.generate()
        b_rotation = create_key_rotation_block(profile_b, new_public_key=b_new.public_key)
        append_block(chain, b_rotation)

        # ``profile``'s key should still be the initial value
        resolved = resolve_did_key(chain, profile.id, initial_key=profile.public_key)
        assert resolved == profile.public_key

        # ``profile_b``'s key resolves to the new one
        resolved_b = resolve_did_key(chain, profile_b.id, initial_key=profile_b.public_key)
        assert resolved_b == b_new.public_key


# ---------------------------------------------------------------------------
# Key-loss recovery scenario (negative test — confirms loss is terminal)
# ---------------------------------------------------------------------------


class TestKeyLossIsTerminal:
    def test_cannot_mint_rotation_without_old_private_key(self) -> None:
        """If the old private key is lost, no party can mint a valid
        KEY_ROTATION block from the public key alone. v1 has no
        recovery path; this test pins down that property."""
        original = synpareia.generate()
        public_only = synpareia.from_public_key(original.public_key)
        new_key = synpareia.generate().public_key
        with pytest.raises(ValueError, match="must hold the current private key"):
            create_key_rotation_block(public_only, new_public_key=new_key)

    def test_a_chain_authoritative_if_no_rotations_minted(
        self, profile: synpareia.Profile, profile_b: synpareia.Profile
    ) -> None:
        """With key loss, the chain has no rotations, so
        ``resolve_did_key`` returns the initial_key — which is now
        operationally useless because nobody can sign. The verifier
        correctly reports the *last known authorised key* but the user
        is locked out at the application layer."""
        from synpareia.policy import templates

        chain = create_chain(profile, policy=templates.sphere(profile, profile_b))
        resolved = resolve_did_key(chain, profile.id, initial_key=profile.public_key)
        assert resolved == profile.public_key  # the lost key — chain knows nothing else

    def test_key_rotation_payload_typed_dataclass(self, profile: synpareia.Profile) -> None:
        """The exposed dataclass is the typed handle callers should
        prefer over manual JSON inspection."""
        new_key = synpareia.generate().public_key
        block = create_key_rotation_block(profile, new_public_key=new_key)
        payload = parse_key_rotation_payload(block)
        assert isinstance(payload, KeyRotationPayload)
        assert payload.did == profile.id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _block_with_content(profile: synpareia.Profile, content: bytes) -> Block:
    """Construct an unsigned KEY_ROTATION block carrying ``content``.

    Used by the parser tests to exercise malformed-payload paths
    without going through the signing pipeline.
    """
    from datetime import UTC, datetime

    from synpareia.hash import content_hash as compute_content_hash

    return Block(
        id="blk_test",
        type=BlockType.KEY_ROTATION,
        author_id=profile.id,
        content_hash=compute_content_hash(content),
        created_at=datetime.now(UTC),
        content=content,
        signature=None,
        metadata={},
    )
