"""Tests for threshold (XOR n-of-n) commitments."""

from __future__ import annotations

import os

import pytest

import synpareia
from synpareia.commitment import verify_commitment
from synpareia.threshold import (
    create_threshold_commitment,
    random_shares,
    verify_threshold_commitment,
    xor_shares,
)


class TestXorShares:
    def test_single_share_returns_itself(self) -> None:
        s = b"\x01\x02\x03\x04"
        assert xor_shares([s]) == s

    def test_two_identical_shares_cancel(self) -> None:
        s = os.urandom(16)
        assert xor_shares([s, s]) == b"\x00" * 16

    def test_two_known_shares(self) -> None:
        a = bytes.fromhex("0102")
        b = bytes.fromhex("0304")
        assert xor_shares([a, b]).hex() == "0206"

    def test_three_shares_associative(self) -> None:
        a = os.urandom(32)
        b = os.urandom(32)
        c = os.urandom(32)
        ab_then_c = xor_shares([xor_shares([a, b]), c])
        abc = xor_shares([a, b, c])
        assert ab_then_c == abc

    def test_order_insensitive(self) -> None:
        a = os.urandom(32)
        b = os.urandom(32)
        c = os.urandom(32)
        assert xor_shares([a, b, c]) == xor_shares([c, a, b])

    def test_leading_zero_preserved(self) -> None:
        """Result length must match input length even when high bytes cancel."""
        a = b"\xff\x00\x00"
        b = b"\xff\x00\x00"
        out = xor_shares([a, b])
        assert out == b"\x00\x00\x00"
        assert len(out) == 3

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one share"):
            xor_shares([])

    def test_length_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="equal length"):
            xor_shares([b"ab", b"abc"])


class TestRandomShares:
    def test_count_and_length(self) -> None:
        shares = random_shares(5, length=16)
        assert len(shares) == 5
        assert all(len(s) == 16 for s in shares)

    def test_default_length_32(self) -> None:
        shares = random_shares(2)
        assert all(len(s) == 32 for s in shares)

    def test_shares_are_distinct(self) -> None:
        shares = random_shares(4, length=32)
        assert len(set(shares)) == 4  # collision probability ~0

    def test_n_below_two_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2"):
            random_shares(1)
        with pytest.raises(ValueError, match="at least 2"):
            random_shares(0)

    def test_zero_length_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 16 bytes"):
            random_shares(2, length=0)

    def test_short_length_raises(self) -> None:
        """Shares shorter than the 128-bit minimum are rejected."""
        with pytest.raises(ValueError, match="at least 16 bytes"):
            random_shares(2, length=15)


class TestCreateThresholdCommitment:
    def test_two_party_round_trip(self) -> None:
        content = b"joint statement"
        shares = random_shares(2)
        commitment, _ = create_threshold_commitment(content, shares)
        assert verify_threshold_commitment(commitment, content, shares)

    def test_three_party_round_trip(self) -> None:
        content = b"three-way attestation"
        shares = random_shares(3)
        commitment, _ = create_threshold_commitment(content, shares)
        assert verify_threshold_commitment(commitment, content, shares)

    def test_joint_nonce_opens_via_single_party_verify(self) -> None:
        """The joint nonce can also be checked with verify_commitment directly."""
        content = b"data"
        shares = random_shares(3)
        commitment, joint = create_threshold_commitment(content, shares)
        assert verify_commitment(commitment, content, joint)

    def test_commitment_hash_is_32_bytes(self) -> None:
        content = b"data"
        shares = random_shares(2)
        commitment, _ = create_threshold_commitment(content, shares)
        assert len(commitment) == 32

    def test_one_share_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2 shares"):
            create_threshold_commitment(b"data", [os.urandom(32)])

    def test_empty_shares_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2 shares"):
            create_threshold_commitment(b"data", [])

    def test_length_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="equal length"):
            create_threshold_commitment(b"data", [os.urandom(16), os.urandom(32)])


class TestVerifyThresholdCommitment:
    def test_tampered_content_rejected(self) -> None:
        shares = random_shares(2)
        commitment, _ = create_threshold_commitment(b"original", shares)
        assert not verify_threshold_commitment(commitment, b"tampered", shares)

    def test_missing_share_rejected(self) -> None:
        """Dropping a share breaks the joint nonce and fails verification."""
        content = b"joint"
        shares = random_shares(3)
        commitment, _ = create_threshold_commitment(content, shares)
        # Supply only the first two shares (need all three under n-of-n).
        assert not verify_threshold_commitment(commitment, content, shares[:2])

    def test_wrong_share_rejected(self) -> None:
        content = b"joint"
        shares = random_shares(2)
        commitment, _ = create_threshold_commitment(content, shares)
        # Swap one share for a random replacement.
        bogus = [shares[0], os.urandom(32)]
        assert not verify_threshold_commitment(commitment, content, bogus)

    def test_single_share_returns_false(self) -> None:
        """One share is below the threshold; returns False, not raise."""
        content = b"x"
        shares = random_shares(2)
        commitment, _ = create_threshold_commitment(content, shares)
        assert not verify_threshold_commitment(commitment, content, [shares[0]])

    def test_empty_shares_returns_false(self) -> None:
        content = b"x"
        shares = random_shares(2)
        commitment, _ = create_threshold_commitment(content, shares)
        assert not verify_threshold_commitment(commitment, content, [])

    def test_length_mismatch_returns_false_not_raise(self) -> None:
        """Malformed share set should verify False, not raise."""
        content = b"x"
        shares = random_shares(2)
        commitment, _ = create_threshold_commitment(content, shares)
        mismatched = [shares[0], shares[1][:-1]]  # one share truncated
        assert not verify_threshold_commitment(commitment, content, mismatched)


class TestMutualAttestationPattern:
    """Neither party can open the commitment alone — core use case (§5.6.4)."""

    def test_alice_alone_cannot_open(self) -> None:
        alice_share = os.urandom(32)
        bob_share = os.urandom(32)
        content = b"alice says: X, bob says: Y"
        commitment, _joint = create_threshold_commitment(content, [alice_share, bob_share])
        # Alice tries with only her share (padded to threshold by duplication attempt)
        assert not verify_threshold_commitment(commitment, content, [alice_share, alice_share])
        # Alice tries with a fabricated "bob-like" share
        fake_bob = os.urandom(32)
        assert not verify_threshold_commitment(commitment, content, [alice_share, fake_bob])

    def test_both_parties_together_open(self) -> None:
        alice_share = os.urandom(32)
        bob_share = os.urandom(32)
        content = b"alice: X; bob: Y"
        commitment, _ = create_threshold_commitment(content, [alice_share, bob_share])
        assert verify_threshold_commitment(commitment, content, [alice_share, bob_share])


class TestPublicAPI:
    def test_reexports_on_top_level(self) -> None:
        assert synpareia.create_threshold_commitment is create_threshold_commitment
        assert synpareia.verify_threshold_commitment is verify_threshold_commitment
        assert synpareia.random_shares is random_shares
        assert synpareia.xor_shares is xor_shares
