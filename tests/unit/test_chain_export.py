"""Tests for chain export and import.

Under v0.3, position 0 in the export is the POLICY genesis block;
message blocks begin at index 1.
"""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

import synpareia
from synpareia.chain.export import verify_export
from synpareia.chain.operations import chain_from_export
from synpareia.types import BlockType

if TYPE_CHECKING:
    from synpareia.policy import Policy

GENESIS_OFFSET = 1  # index 0 in positions[] is the POLICY block


class TestExport:
    def test_export_round_trip(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        for i in range(3):
            chain.append(synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}"))

        data = synpareia.export_chain(chain)
        assert data["version"] == "1.0"
        assert data["chain_id"] == chain.id
        assert len(data["positions"]) == GENESIS_OFFSET + 3
        assert data["policy_hash"] is not None

        imported = chain_from_export(data)
        assert imported.id == chain.id
        assert imported.length == GENESIS_OFFSET + 3
        assert imported.policy_hash == chain.policy_hash
        valid, errors = imported.verify(public_keys={profile.id: profile.public_key})
        assert valid, errors

    def test_export_without_content(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "secret"))

        data = synpareia.export_chain(chain, include_content=False)
        assert all("content" not in p["block"] for p in data["positions"])

    def test_export_with_content(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "visible"))

        data = synpareia.export_chain(chain, include_content=True)
        assert "content" in data["positions"][GENESIS_OFFSET]["block"]

    def test_export_preserves_signatures(
        self, profile: synpareia.Profile, cop_policy: Policy
    ) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        block = synpareia.create_block(profile, BlockType.MESSAGE, "signed")
        chain.append(block)

        data = synpareia.export_chain(chain)
        assert data["positions"][GENESIS_OFFSET]["block"]["signature"] is not None


class TestVerifyExport:
    def test_valid_export(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        for i in range(3):
            chain.append(synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}"))
        data = synpareia.export_chain(chain)
        valid, errors = verify_export(data, public_keys={profile.id: profile.public_key})
        assert valid, errors

    def test_tampered_position_hash(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "test"))
        data = synpareia.export_chain(chain)

        data_copy = copy.deepcopy(data)
        data_copy["positions"][GENESIS_OFFSET]["position_hash"] = "00" * 32
        valid, _ = verify_export(data_copy, public_keys={profile.id: profile.public_key})
        assert not valid

    def test_tampered_content(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "original"))
        data = synpareia.export_chain(chain)

        data_copy = copy.deepcopy(data)
        data_copy["positions"][GENESIS_OFFSET]["block"]["content"] = b"tampered".hex()
        valid, errors = verify_export(data_copy, public_keys={profile.id: profile.public_key})
        assert not valid
        assert any("content_hash" in e for e in errors)

    def test_tampered_head_hash(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "test"))
        data = synpareia.export_chain(chain)

        data_copy = copy.deepcopy(data)
        data_copy["head_hash"] = "ff" * 32
        valid, errors = verify_export(data_copy, public_keys={profile.id: profile.public_key})
        assert not valid
        assert any("head_hash" in e for e in errors)

    def test_broken_parent_hash_linkage(
        self, profile: synpareia.Profile, cop_policy: Policy
    ) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "first"))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "second"))
        data = synpareia.export_chain(chain)

        data_copy = copy.deepcopy(data)
        data_copy["positions"][GENESIS_OFFSET + 1]["parent_hash"] = "00" * 32
        valid, _ = verify_export(data_copy, public_keys={profile.id: profile.public_key})
        assert not valid

    def test_tampered_signature_rejected(
        self, profile: synpareia.Profile, cop_policy: Policy
    ) -> None:
        """verify_export must Ed25519-verify signatures when public_keys is supplied."""
        chain = synpareia.create_chain(profile, policy=cop_policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "original"))
        data = synpareia.export_chain(chain)

        data_copy = copy.deepcopy(data)
        sig_hex = data_copy["positions"][GENESIS_OFFSET]["block"]["signature"]
        # Flip first byte of the signature
        sig_bytes = bytearray(bytes.fromhex(sig_hex))
        sig_bytes[0] ^= 0x01
        data_copy["positions"][GENESIS_OFFSET]["block"]["signature"] = sig_bytes.hex()

        valid, errors = verify_export(data_copy, public_keys={profile.id: profile.public_key})
        assert not valid
        assert any("signature verification failed" in e for e in errors)

    def test_signatures_without_keys_fails_closed(
        self, profile: synpareia.Profile, cop_policy: Policy
    ) -> None:
        """verify_export must fail closed when signed blocks lack public_keys."""
        chain = synpareia.create_chain(profile, policy=cop_policy)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "signed"))
        data = synpareia.export_chain(chain)
        valid, errors = verify_export(data)  # no public_keys
        assert not valid
        assert any("public_keys not supplied" in e for e in errors)


class TestGenesisPolicy:
    def test_genesis_block_is_policy(self, profile: synpareia.Profile, cop_policy: Policy) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        data = synpareia.export_chain(chain)
        assert data["positions"][0]["block"]["type"] == "policy"
        assert data["positions"][0]["block"]["content_hash"] == data["policy_hash"]

    def test_tampered_policy_hash_fails_verify(
        self, profile: synpareia.Profile, cop_policy: Policy
    ) -> None:
        chain = synpareia.create_chain(profile, policy=cop_policy)
        data = synpareia.export_chain(chain)
        data["policy_hash"] = "00" * 32
        valid, errors = verify_export(data)
        assert not valid
        assert any("policy" in e.lower() for e in errors)
