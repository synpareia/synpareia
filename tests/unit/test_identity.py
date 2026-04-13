"""Tests for identity: keypair generation, DID derivation, profile loading."""

from __future__ import annotations

import base64
import hashlib

import synpareia
from synpareia.types import DID_PREFIX


class TestGenerate:
    def test_generates_profile(self) -> None:
        profile = synpareia.generate()
        assert isinstance(profile, synpareia.Profile)
        assert profile.id.startswith(DID_PREFIX)
        assert len(profile.public_key) == 32
        assert profile.private_key is not None
        assert len(profile.private_key) == 32

    def test_two_profiles_differ(self) -> None:
        a = synpareia.generate()
        b = synpareia.generate()
        assert a.id != b.id
        assert a.public_key != b.public_key

    def test_did_is_deterministic(self) -> None:
        profile = synpareia.generate()
        expected = DID_PREFIX + hashlib.sha256(profile.public_key).hexdigest()
        assert profile.id == expected


class TestFromPrivateKey:
    def test_round_trip(self) -> None:
        original = synpareia.generate()
        restored = synpareia.from_private_key(original.private_key)
        assert restored.id == original.id
        assert restored.public_key == original.public_key
        assert restored.private_key == original.private_key


class TestFromPublicKey:
    def test_public_only(self) -> None:
        original = synpareia.generate()
        public_only = synpareia.from_public_key(original.public_key)
        assert public_only.id == original.id
        assert public_only.public_key == original.public_key
        assert public_only.private_key is None


class TestLoad:
    def test_load_with_both_keys(self) -> None:
        original = synpareia.generate()
        pub_b64 = base64.b64encode(original.public_key).decode()
        priv_b64 = base64.b64encode(original.private_key).decode()
        loaded = synpareia.identity.load(pub_b64, priv_b64)
        assert loaded.id == original.id
        assert loaded.private_key == original.private_key

    def test_load_public_only(self) -> None:
        original = synpareia.generate()
        pub_b64 = base64.b64encode(original.public_key).decode()
        loaded = synpareia.identity.load(pub_b64)
        assert loaded.id == original.id
        assert loaded.private_key is None
