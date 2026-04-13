"""Tests for Ed25519 signing and verification."""

from __future__ import annotations

import synpareia
from synpareia.signing import sign, verify


class TestSignVerify:
    def test_round_trip(self, profile: synpareia.Profile) -> None:
        data = b"hello world"
        sig = sign(profile.private_key, data)
        assert verify(profile.public_key, data, sig)

    def test_wrong_key_rejects(self, profile: synpareia.Profile) -> None:
        other = synpareia.generate()
        data = b"hello world"
        sig = sign(profile.private_key, data)
        assert not verify(other.public_key, data, sig)

    def test_tampered_data_rejects(self, profile: synpareia.Profile) -> None:
        data = b"hello world"
        sig = sign(profile.private_key, data)
        assert not verify(profile.public_key, b"tampered", sig)

    def test_signature_is_64_bytes(self, profile: synpareia.Profile) -> None:
        sig = sign(profile.private_key, b"data")
        assert len(sig) == 64

    def test_invalid_signature_bytes(self, profile: synpareia.Profile) -> None:
        assert not verify(profile.public_key, b"data", b"not a signature")
