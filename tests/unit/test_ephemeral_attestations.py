"""Offline tests for §8.2 ephemeral attestation dataclasses.

These exercise the SDK's envelope builders + verifiers without a
network round-trip. The witness integration tests cover the on-wire
round-trip.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime

import pytest

from synpareia import generate
from synpareia.signing import sign as ed25519_sign
from synpareia.signing import verify as ed25519_verify
from synpareia.witness.ephemeral import (
    ArbitrationAttestation,
    FairExchangeAttestation,
    LivenessRelayAttestation,
    QueryAttestation,
    RandomnessAttestation,
    RevealPayload,
    VerifyAttestation,
    build_arbitration_envelope,
    build_fair_exchange_envelope,
    build_liveness_relay_envelope,
    build_query_envelope,
    build_randomness_envelope,
    build_verify_envelope,
    build_vrf_input_payload,
    sign_attestation,
    vrf_random_from_signature,
)


@pytest.fixture
def witness_keys() -> tuple[bytes, bytes]:
    """Fresh witness keypair for each test."""
    profile = generate()
    assert profile.private_key is not None
    return profile.private_key, profile.public_key


@pytest.fixture
def witness_id() -> str:
    return "did:synpareia:" + "a" * 64


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)


class TestLivenessRelay:
    def test_verify_roundtrip(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        priv, pub = witness_keys
        ch = hashlib.sha256(b"c").digest()
        rh = hashlib.sha256(b"r").digest()
        env = build_liveness_relay_envelope(
            witness_id,
            now,
            challenger_did="did:synpareia:" + "b" * 64,
            responder_did="did:synpareia:" + "c" * 64,
            challenge_hash_hex=ch.hex(),
            response_hash_hex=rh.hex(),
        )
        sig = sign_attestation(priv, env)
        att = LivenessRelayAttestation(
            witness_id=witness_id,
            attestation_time=now,
            challenger_did="did:synpareia:" + "b" * 64,
            responder_did="did:synpareia:" + "c" * 64,
            challenge_hash=ch,
            response_hash=rh,
            signing_envelope=env,
            witness_signature=sig,
        )
        assert att.verify(pub)

    def test_tampered_envelope_fails(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        priv, pub = witness_keys
        env = build_liveness_relay_envelope(
            witness_id,
            now,
            challenger_did="did:synpareia:" + "b" * 64,
            responder_did="did:synpareia:" + "c" * 64,
            challenge_hash_hex="aa" * 32,
            response_hash_hex="bb" * 32,
        )
        sig = sign_attestation(priv, env)
        # Build attestation with DIFFERENT challenger_did than envelope bound
        att = LivenessRelayAttestation(
            witness_id=witness_id,
            attestation_time=now,
            challenger_did="did:synpareia:" + "ff" * 32,
            responder_did="did:synpareia:" + "c" * 64,
            challenge_hash=bytes.fromhex("aa" * 32),
            response_hash=bytes.fromhex("bb" * 32),
            signing_envelope=env,
            witness_signature=sig,
        )
        assert not att.verify(pub)

    def test_wrong_key_fails(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        priv, _pub = witness_keys
        other_pub = generate().public_key
        env = build_liveness_relay_envelope(
            witness_id,
            now,
            challenger_did="did:synpareia:" + "b" * 64,
            responder_did="did:synpareia:" + "c" * 64,
            challenge_hash_hex="aa" * 32,
            response_hash_hex="bb" * 32,
        )
        sig = sign_attestation(priv, env)
        att = LivenessRelayAttestation(
            witness_id=witness_id,
            attestation_time=now,
            challenger_did="did:synpareia:" + "b" * 64,
            responder_did="did:synpareia:" + "c" * 64,
            challenge_hash=bytes.fromhex("aa" * 32),
            response_hash=bytes.fromhex("bb" * 32),
            signing_envelope=env,
            witness_signature=sig,
        )
        assert not att.verify(other_pub)


class TestVerifyAttestation:
    def test_roundtrip(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        priv, pub = witness_keys
        signer_pub = generate().public_key
        env = build_verify_envelope(
            witness_id,
            now,
            envelope_digest_hex="a" * 64,
            signer_public_key_hex=signer_pub.hex(),
            signature_digest_hex="b" * 64,
            result="valid",
        )
        sig = sign_attestation(priv, env)
        att = VerifyAttestation(
            witness_id=witness_id,
            attestation_time=now,
            envelope_digest=bytes.fromhex("a" * 64),
            signer_public_key=signer_pub,
            signature_digest=bytes.fromhex("b" * 64),
            result="valid",
            signing_envelope=env,
            witness_signature=sig,
        )
        assert att.verify(pub)

    def test_covers_helper_binds_envelope_to_attestation(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        """Regression for E2 (2026-04-21 red-team): ``VerifyAttestation.covers``
        must only return True when the caller-supplied envelope hashes to
        the attestation's envelope_digest AND result=valid AND the
        witness signature verifies."""
        priv, pub = witness_keys
        signer_pub = generate().public_key
        real_envelope = b'{"canonical":"bytes"}'
        real_digest = hashlib.sha256(real_envelope).digest()
        env = build_verify_envelope(
            witness_id,
            now,
            envelope_digest_hex=real_digest.hex(),
            signer_public_key_hex=signer_pub.hex(),
            signature_digest_hex="b" * 64,
            result="valid",
        )
        sig = sign_attestation(priv, env)
        att = VerifyAttestation(
            witness_id=witness_id,
            attestation_time=now,
            envelope_digest=real_digest,
            signer_public_key=signer_pub,
            signature_digest=bytes.fromhex("b" * 64),
            result="valid",
            signing_envelope=env,
            witness_signature=sig,
        )
        assert att.covers(real_envelope, pub) is True
        assert att.covers(b'{"other":"bytes"}', pub) is False

    def test_covers_rejects_invalid_result(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        priv, pub = witness_keys
        signer_pub = generate().public_key
        real_envelope = b'{"canonical":"bytes"}'
        real_digest = hashlib.sha256(real_envelope).digest()
        env = build_verify_envelope(
            witness_id,
            now,
            envelope_digest_hex=real_digest.hex(),
            signer_public_key_hex=signer_pub.hex(),
            signature_digest_hex="b" * 64,
            result="invalid",
        )
        sig = sign_attestation(priv, env)
        att = VerifyAttestation(
            witness_id=witness_id,
            attestation_time=now,
            envelope_digest=real_digest,
            signer_public_key=signer_pub,
            signature_digest=bytes.fromhex("b" * 64),
            result="invalid",
            signing_envelope=env,
            witness_signature=sig,
        )
        # covers() only returns True for result=valid — an invalid
        # attestation doesn't prove the envelope was well-signed.
        assert att.covers(real_envelope, pub) is False


class TestArbitrationAttestation:
    def test_roundtrip(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        priv, pub = witness_keys
        ctx = hashlib.sha256(b"ctx").digest()
        env = build_arbitration_envelope(
            witness_id,
            now,
            predicate_name="deadline",
            context_hash_hex=ctx.hex(),
            caller_claimed_outcome="met",
        )
        sig = sign_attestation(priv, env)
        att = ArbitrationAttestation(
            witness_id=witness_id,
            attestation_time=now,
            predicate_name="deadline",
            context_hash=ctx,
            caller_claimed_outcome="met",
            signing_envelope=env,
            witness_signature=sig,
        )
        assert att.verify(pub)

    def test_v1_stub_flag_bound_in_envelope(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        """Regression for E4 (2026-04-21 red-team): ``v1_stub: true`` must
        be part of the signed bytes so a future predicate-DSL verifier
        cannot mistake this record for a witness-adjudicated outcome."""
        _priv, _pub = witness_keys
        ctx = hashlib.sha256(b"ctx").digest()
        env = build_arbitration_envelope(
            witness_id,
            now,
            predicate_name="deadline",
            context_hash_hex=ctx.hex(),
            caller_claimed_outcome="met",
        )
        assert b'"v1_stub":true' in env
        assert b'"caller_claimed_outcome":"met"' in env


class TestRandomnessAttestation:
    def test_roundtrip_verifies_vrf(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        priv, pub = witness_keys
        caller_input = "seed-42"
        vrf_input = build_vrf_input_payload(witness_id, caller_input=caller_input)
        vrf_sig = ed25519_sign(priv, vrf_input)
        random = vrf_random_from_signature(vrf_sig)
        env = build_randomness_envelope(
            witness_id,
            now,
            caller_input=caller_input,
            vrf_signature_hex=vrf_sig.hex(),
            random_hex=random.hex(),
        )
        sig = sign_attestation(priv, env)
        att = RandomnessAttestation(
            witness_id=witness_id,
            attestation_time=now,
            caller_input=caller_input,
            vrf_signature=vrf_sig,
            random=random,
            signing_envelope=env,
            witness_signature=sig,
        )
        assert att.verify(pub)

    def test_random_not_matching_sig_fails(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        """If random != SHA-256(vrf_signature), offline verify must reject.

        This catches a server that returns a random unrelated to the VRF
        signature — the signature might verify in isolation, but the
        VRF consistency check rejects the attestation.
        """
        priv, pub = witness_keys
        caller_input = "seed-42"
        vrf_input = build_vrf_input_payload(witness_id, caller_input=caller_input)
        vrf_sig = ed25519_sign(priv, vrf_input)
        bogus_random = b"\xff" * 32
        env = build_randomness_envelope(
            witness_id,
            now,
            caller_input=caller_input,
            vrf_signature_hex=vrf_sig.hex(),
            random_hex=bogus_random.hex(),
        )
        sig = sign_attestation(priv, env)
        att = RandomnessAttestation(
            witness_id=witness_id,
            attestation_time=now,
            caller_input=caller_input,
            vrf_signature=vrf_sig,
            random=bogus_random,
            signing_envelope=env,
            witness_signature=sig,
        )
        assert not att.verify(pub)

    def test_vrf_is_deterministic(self, witness_keys: tuple[bytes, bytes]) -> None:
        """Pure Ed25519 signatures are deterministic, so VRF output is too."""
        priv, _pub = witness_keys
        a = ed25519_sign(priv, b"x")
        b = ed25519_sign(priv, b"x")
        assert a == b

    def test_vrf_signature_is_not_oracle_for_other_envelopes(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        """Regression for E1 (2026-04-21 red-team): the randomness
        endpoint must not produce signatures that validate as any other
        witness-signed envelope.

        Pre-fix: ``attest_randomness`` signed raw ``caller_input.encode()``,
        so an attacker could submit an arbitrary envelope as caller_input
        and receive a witness signature over it — forging seals, query
        attestations, etc. The domain-separated VRF payload makes the
        signed bytes structurally incompatible with any other envelope.
        """
        priv, pub = witness_keys
        # An attacker crafts a query envelope and tries to get the
        # randomness endpoint to sign it for them.
        target_envelope = build_query_envelope(
            witness_id,
            now,
            query_key="is_alive",
            query_context="",
            answer="yes",
        )
        # They submit the raw bytes as caller_input
        malicious_input = target_envelope.decode("utf-8", errors="ignore")
        vrf_input = build_vrf_input_payload(witness_id, caller_input=malicious_input)
        vrf_sig = ed25519_sign(priv, vrf_input)
        # The attacker now holds a valid signature over vrf_input, but
        # vrf_input is NOT equal to target_envelope — so they cannot
        # forge a query attestation.
        assert vrf_input != target_envelope
        assert not ed25519_verify(pub, target_envelope, vrf_sig)


class TestQueryAttestation:
    def test_roundtrip(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        priv, pub = witness_keys
        env = build_query_envelope(
            witness_id, now, query_key="is_alive", query_context="", answer="yes"
        )
        sig = sign_attestation(priv, env)
        att = QueryAttestation(
            witness_id=witness_id,
            attestation_time=now,
            query_key="is_alive",
            query_context="",
            answer="yes",
            signing_envelope=env,
            witness_signature=sig,
        )
        assert att.verify(pub)

    def test_max_age_seconds_rejects_stale(
        self, witness_keys: tuple[bytes, bytes], witness_id: str
    ) -> None:
        """Regression for E6 (2026-04-21 red-team): query attestations
        don't bind a recipient, so liveness semantics require callers
        to pass ``max_age_seconds`` and fail closed on stale payloads."""
        from datetime import UTC, timedelta
        from datetime import datetime as _dt

        priv, pub = witness_keys
        stale = _dt.now(UTC) - timedelta(hours=1)
        env = build_query_envelope(
            witness_id, stale, query_key="is_alive", query_context="", answer="yes"
        )
        sig = sign_attestation(priv, env)
        att = QueryAttestation(
            witness_id=witness_id,
            attestation_time=stale,
            query_key="is_alive",
            query_context="",
            answer="yes",
            signing_envelope=env,
            witness_signature=sig,
        )
        # No age check → pass (signature + envelope still match).
        assert att.verify(pub) is True
        # 60-second bound → reject the hour-old attestation.
        assert att.verify(pub, max_age_seconds=60) is False


class TestFairExchangeAttestation:
    def test_roundtrip(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        priv, pub = witness_keys
        nonce_a, content_a = os.urandom(16), b"A"
        nonce_b, content_b = os.urandom(16), b"B"
        ch_a = hashlib.sha256(nonce_a + content_a).digest()
        ch_b = hashlib.sha256(nonce_b + content_b).digest()
        env = build_fair_exchange_envelope(
            witness_id,
            now,
            party_a_did="did:synpareia:" + "a" * 64,
            party_a_committed_hash=ch_a.hex(),
            party_b_did="did:synpareia:" + "b" * 64,
            party_b_committed_hash=ch_b.hex(),
            released=True,
        )
        sig = sign_attestation(priv, env)
        att = FairExchangeAttestation(
            witness_id=witness_id,
            attestation_time=now,
            released=True,
            party_a=RevealPayload(
                did="did:synpareia:" + "a" * 64,
                committed_hash=ch_a,
                nonce=nonce_a,
                content=content_a,
            ),
            party_b=RevealPayload(
                did="did:synpareia:" + "b" * 64,
                committed_hash=ch_b,
                nonce=nonce_b,
                content=content_b,
            ),
            signing_envelope=env,
            witness_signature=sig,
        )
        assert att.verify(pub)

    def test_swapped_parties_fails(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        """Offline verifier rejects if the attestation swaps a/b but
        the envelope didn't — binding must be order-sensitive."""
        priv, pub = witness_keys
        nonce_a, content_a = os.urandom(16), b"A"
        nonce_b, content_b = os.urandom(16), b"B"
        ch_a = hashlib.sha256(nonce_a + content_a).digest()
        ch_b = hashlib.sha256(nonce_b + content_b).digest()
        env = build_fair_exchange_envelope(
            witness_id,
            now,
            party_a_did="did:synpareia:" + "a" * 64,
            party_a_committed_hash=ch_a.hex(),
            party_b_did="did:synpareia:" + "b" * 64,
            party_b_committed_hash=ch_b.hex(),
            released=True,
        )
        sig = sign_attestation(priv, env)
        att = FairExchangeAttestation(
            witness_id=witness_id,
            attestation_time=now,
            released=True,
            party_a=RevealPayload(
                did="did:synpareia:" + "b" * 64,  # swapped DID
                committed_hash=ch_b,
                nonce=nonce_b,
                content=content_b,
            ),
            party_b=RevealPayload(
                did="did:synpareia:" + "a" * 64,
                committed_hash=ch_a,
                nonce=nonce_a,
                content=content_a,
            ),
            signing_envelope=env,
            witness_signature=sig,
        )
        assert not att.verify(pub)

    def test_tampered_content_rejected_at_construction(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        """Regression for E3 (2026-04-21 red-team): a FairExchangeAttestation
        whose ``content`` doesn't hash to ``committed_hash`` must not even
        be constructible. This closes the consumer footgun of trusting
        ``.party_a.content`` as an authenticated field."""
        priv, _pub = witness_keys
        nonce_a, content_a = os.urandom(16), b"genuine A content"
        nonce_b, content_b = os.urandom(16), b"genuine B content"
        ch_a = hashlib.sha256(nonce_a + content_a).digest()
        ch_b = hashlib.sha256(nonce_b + content_b).digest()
        env = build_fair_exchange_envelope(
            witness_id,
            now,
            party_a_did="did:synpareia:" + "a" * 64,
            party_a_committed_hash=ch_a.hex(),
            party_b_did="did:synpareia:" + "b" * 64,
            party_b_committed_hash=ch_b.hex(),
            released=True,
        )
        sig = sign_attestation(priv, env)
        with pytest.raises(ValueError, match="party_a: committed_hash"):
            FairExchangeAttestation(
                witness_id=witness_id,
                attestation_time=now,
                released=True,
                party_a=RevealPayload(
                    did="did:synpareia:" + "a" * 64,
                    committed_hash=ch_a,
                    nonce=nonce_a,
                    content=b"TAMPERED A content",
                ),
                party_b=RevealPayload(
                    did="did:synpareia:" + "b" * 64,
                    committed_hash=ch_b,
                    nonce=nonce_b,
                    content=content_b,
                ),
                signing_envelope=env,
                witness_signature=sig,
            )


class TestCrossTypeSubstitutionRejected:
    """Different attestation types carry a `attestation_type` field in
    the envelope, so a signature over a liveness-relay envelope does
    not validate against a query envelope with the same witness."""

    def test_cannot_substitute_liveness_for_query(
        self, witness_keys: tuple[bytes, bytes], witness_id: str, now: datetime
    ) -> None:
        priv, pub = witness_keys
        liveness_env = build_liveness_relay_envelope(
            witness_id,
            now,
            challenger_did="did:synpareia:" + "b" * 64,
            responder_did="did:synpareia:" + "c" * 64,
            challenge_hash_hex="aa" * 32,
            response_hash_hex="bb" * 32,
        )
        liveness_sig = sign_attestation(priv, liveness_env)

        # Try to repackage the liveness signature as a query attestation
        forged = QueryAttestation(
            witness_id=witness_id,
            attestation_time=now,
            query_key="is_alive",
            query_context="",
            answer="yes",
            signing_envelope=liveness_env,
            witness_signature=liveness_sig,
        )
        assert not forged.verify(pub)
