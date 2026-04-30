"""Ephemeral attestation envelopes (§8.2) + offline verifiers.

The witness produces these attestations and returns them to the
requester. Nothing is persisted server-side. The SDK ships the
signing-envelope builders and offline verifiers so callers can check
witness signatures without a network round-trip.

Every attestation is a JCS-canonicalized object the witness signs with
its Ed25519 key. Offline verification:

    1. Reconstruct the signing envelope bytes.
    2. Compare to the ``signing_envelope`` bytes returned by the witness
       (defence in depth against client/server drift).
    3. Ed25519-verify the signature against the witness public key.

A verifier that skips step 2 still catches tampering via step 3; step 2
catches pre-verification divergence faster and with a clearer error.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from synpareia.hash import jcs_canonicalize
from synpareia.signing import sign as ed25519_sign
from synpareia.signing import verify as ed25519_verify

if TYPE_CHECKING:
    from datetime import datetime

__all__ = [
    "ArbitrationAttestation",
    "EphemeralAttestation",
    "FairExchangeAttestation",
    "LivenessRelayAttestation",
    "QueryAttestation",
    "RandomnessAttestation",
    "RevealPayload",
    "VerifyAttestation",
    "build_arbitration_envelope",
    "build_fair_exchange_envelope",
    "build_liveness_relay_envelope",
    "build_query_envelope",
    "build_randomness_envelope",
    "build_verify_envelope",
    "build_vrf_input_payload",
    "sign_attestation",
    "verify_attestation",
    "vrf_random_from_signature",
]


# ─── Canonicalization helpers ───────────────────────────────────────


def _canonical_time(t: datetime) -> str:
    """Canonical string form of an attestation timestamp.

    Forces UTC and the isoformat produced by a UTC-aware datetime so
    envelopes built from a non-UTC but equivalent datetime still match
    byte-for-byte. Closes E5 from the 2026-04-21 red-team review.
    """
    from datetime import UTC

    return t.astimezone(UTC).isoformat()


def build_vrf_input_payload(
    witness_id: str,
    *,
    caller_input: str,
) -> bytes:
    """Canonical domain-separated bytes the witness signs for VRF.

    Without this wrapper the randomness endpoint would be a signing
    oracle: any caller-chosen bytes (e.g. a forged seal envelope) could
    be slipped in as ``caller_input`` and the witness would return a
    valid Ed25519 signature over them. The ``domain: "vrf-v1"`` prefix
    and the JCS object structure guarantee the signed bytes cannot
    collide with any other envelope type the witness signs. Closes E1
    from the 2026-04-21 red-team review.

    Intentionally excludes ``attestation_time`` so Pure Ed25519
    determinism is preserved — same ``caller_input`` from the same
    witness always produces the same VRF signature.
    """
    return jcs_canonicalize(
        {
            "domain": "vrf-v1",
            "witness_id": witness_id,
            "caller_input": caller_input,
        }
    )


# ─── Envelope builders ──────────────────────────────────────────────


def _base_envelope(
    attestation_type: str, witness_id: str, attestation_time: datetime
) -> dict[str, Any]:
    return {
        "attestation_type": attestation_type,
        "attestation_time": _canonical_time(attestation_time),
        "witness_id": witness_id,
    }


def build_liveness_relay_envelope(
    witness_id: str,
    attestation_time: datetime,
    *,
    challenger_did: str,
    responder_did: str,
    challenge_hash_hex: str,
    response_hash_hex: str,
) -> bytes:
    env = _base_envelope("liveness_relay", witness_id, attestation_time)
    env["challenger_did"] = challenger_did
    env["responder_did"] = responder_did
    env["challenge_hash"] = challenge_hash_hex
    env["response_hash"] = response_hash_hex
    return jcs_canonicalize(env)


def build_verify_envelope(
    witness_id: str,
    attestation_time: datetime,
    *,
    envelope_digest_hex: str,
    signer_public_key_hex: str,
    signature_digest_hex: str,
    result: Literal["valid", "invalid"],
) -> bytes:
    env = _base_envelope("verify", witness_id, attestation_time)
    env["envelope_digest"] = envelope_digest_hex
    env["signer_public_key"] = signer_public_key_hex
    env["signature_digest"] = signature_digest_hex
    env["result"] = result
    return jcs_canonicalize(env)


def build_arbitration_envelope(
    witness_id: str,
    attestation_time: datetime,
    *,
    predicate_name: str,
    context_hash_hex: str,
    caller_claimed_outcome: str,
) -> bytes:
    """Build the canonical envelope the witness signs for an arbitration.

    The v1 stub is strictly a co-sign of what the caller claimed — the
    witness does not evaluate the predicate. ``v1_stub: true`` is bound
    into the envelope so a future predicate-DSL verifier cannot confuse
    this with a witness-adjudicated outcome.
    """
    env = _base_envelope("arbitrate", witness_id, attestation_time)
    env["predicate_name"] = predicate_name
    env["context_hash"] = context_hash_hex
    env["caller_claimed_outcome"] = caller_claimed_outcome
    env["status"] = "recorded"
    env["v1_stub"] = True
    return jcs_canonicalize(env)


def build_randomness_envelope(
    witness_id: str,
    attestation_time: datetime,
    *,
    caller_input: str,
    vrf_signature_hex: str,
    random_hex: str,
) -> bytes:
    env = _base_envelope("randomness", witness_id, attestation_time)
    env["caller_input"] = caller_input
    env["vrf_signature"] = vrf_signature_hex
    env["random"] = random_hex
    return jcs_canonicalize(env)


def build_query_envelope(
    witness_id: str,
    attestation_time: datetime,
    *,
    query_key: str,
    query_context: str,
    answer: str,
) -> bytes:
    env = _base_envelope("query", witness_id, attestation_time)
    env["query_key"] = query_key
    env["query_context"] = query_context
    env["answer"] = answer
    return jcs_canonicalize(env)


def build_fair_exchange_envelope(
    witness_id: str,
    attestation_time: datetime,
    *,
    party_a_did: str,
    party_a_committed_hash: str,
    party_b_did: str,
    party_b_committed_hash: str,
    released: bool,
) -> bytes:
    env: dict[str, Any] = {
        "attestation_type": "fair_exchange",
        "attestation_time": _canonical_time(attestation_time),
        "witness_id": witness_id,
        "party_a_did": party_a_did,
        "party_a_committed_hash": party_a_committed_hash,
        "party_b_did": party_b_did,
        "party_b_committed_hash": party_b_committed_hash,
        "released": released,
    }
    return jcs_canonicalize(env)


# ─── Typed attestation payloads ────────────────────────────────────


@dataclass(frozen=True)
class LivenessRelayAttestation:
    witness_id: str
    attestation_time: datetime
    challenger_did: str
    responder_did: str
    challenge_hash: bytes
    response_hash: bytes
    signing_envelope: bytes
    witness_signature: bytes

    def verify(self, witness_public_key: bytes) -> bool:
        expected = build_liveness_relay_envelope(
            self.witness_id,
            self.attestation_time,
            challenger_did=self.challenger_did,
            responder_did=self.responder_did,
            challenge_hash_hex=self.challenge_hash.hex(),
            response_hash_hex=self.response_hash.hex(),
        )
        if expected != self.signing_envelope:
            return False
        return ed25519_verify(witness_public_key, self.signing_envelope, self.witness_signature)


@dataclass(frozen=True)
class VerifyAttestation:
    witness_id: str
    attestation_time: datetime
    envelope_digest: bytes
    signer_public_key: bytes
    signature_digest: bytes
    result: Literal["valid", "invalid"]
    signing_envelope: bytes
    witness_signature: bytes

    def verify(self, witness_public_key: bytes) -> bool:
        expected = build_verify_envelope(
            self.witness_id,
            self.attestation_time,
            envelope_digest_hex=self.envelope_digest.hex(),
            signer_public_key_hex=self.signer_public_key.hex(),
            signature_digest_hex=self.signature_digest.hex(),
            result=self.result,
        )
        if expected != self.signing_envelope:
            return False
        return ed25519_verify(witness_public_key, self.signing_envelope, self.witness_signature)

    def covers(self, envelope_bytes: bytes, witness_public_key: bytes) -> bool:
        """Return True iff this attestation is a valid witness claim
        that ``envelope_bytes`` was signed by ``self.signer_public_key``
        with result == "valid".

        Closes the E2 footgun: the attestation's ``envelope_digest``
        alone proves nothing without the caller-supplied canonical bytes
        it covers. This helper hashes those bytes, compares, and
        delegates to ``verify()`` — all three checks must pass.
        """
        if hashlib.sha256(envelope_bytes).digest() != self.envelope_digest:
            return False
        if self.result != "valid":
            return False
        return self.verify(witness_public_key)


@dataclass(frozen=True)
class ArbitrationAttestation:
    witness_id: str
    attestation_time: datetime
    predicate_name: str
    context_hash: bytes
    caller_claimed_outcome: str
    signing_envelope: bytes
    witness_signature: bytes

    def verify(self, witness_public_key: bytes) -> bool:
        expected = build_arbitration_envelope(
            self.witness_id,
            self.attestation_time,
            predicate_name=self.predicate_name,
            context_hash_hex=self.context_hash.hex(),
            caller_claimed_outcome=self.caller_claimed_outcome,
        )
        if expected != self.signing_envelope:
            return False
        return ed25519_verify(witness_public_key, self.signing_envelope, self.witness_signature)


@dataclass(frozen=True)
class RandomnessAttestation:
    witness_id: str
    attestation_time: datetime
    caller_input: str
    vrf_signature: bytes
    random: bytes
    signing_envelope: bytes
    witness_signature: bytes

    def verify(self, witness_public_key: bytes) -> bool:
        """Verify envelope + witness signature + VRF consistency.

        Four checks:
        1. envelope matches expected JCS bytes
        2. witness signature valid over envelope
        3. ``random`` equals SHA-256(``vrf_signature``)
        4. ``vrf_signature`` is a valid Ed25519 signature by the witness
           over ``build_vrf_input_payload(...)`` — the domain-separated
           payload, NOT raw ``caller_input.encode()``. This prevents
           the randomness endpoint becoming a signing oracle.
        """
        expected = build_randomness_envelope(
            self.witness_id,
            self.attestation_time,
            caller_input=self.caller_input,
            vrf_signature_hex=self.vrf_signature.hex(),
            random_hex=self.random.hex(),
        )
        if expected != self.signing_envelope:
            return False
        if not ed25519_verify(witness_public_key, self.signing_envelope, self.witness_signature):
            return False
        if self.random != hashlib.sha256(self.vrf_signature).digest():
            return False
        vrf_input = build_vrf_input_payload(
            self.witness_id,
            caller_input=self.caller_input,
        )
        return ed25519_verify(witness_public_key, vrf_input, self.vrf_signature)


@dataclass(frozen=True)
class QueryAttestation:
    witness_id: str
    attestation_time: datetime
    query_key: str
    query_context: str
    answer: str
    signing_envelope: bytes
    witness_signature: bytes

    def verify(
        self,
        witness_public_key: bytes,
        *,
        max_age_seconds: float | None = None,
    ) -> bool:
        """Verify envelope + witness signature, optionally fail closed
        on stale attestations.

        ``query_context`` is not tied to a recipient, so e.g. an
        ``is_alive=yes`` attestation from 30s ago is byte-identical to
        one an attacker replays 30 days later. Callers that depend on
        liveness semantics should pass ``max_age_seconds`` (E6 from the
        2026-04-21 red-team). A nonce'd ``query_context`` is the
        stronger option when consumers control the call.
        """
        expected = build_query_envelope(
            self.witness_id,
            self.attestation_time,
            query_key=self.query_key,
            query_context=self.query_context,
            answer=self.answer,
        )
        if expected != self.signing_envelope:
            return False
        if max_age_seconds is not None:
            from datetime import UTC
            from datetime import datetime as _dt

            age = (_dt.now(UTC) - self.attestation_time).total_seconds()
            if age > max_age_seconds or age < 0:
                return False
        return ed25519_verify(witness_public_key, self.signing_envelope, self.witness_signature)


@dataclass(frozen=True)
class RevealPayload:
    did: str
    committed_hash: bytes
    nonce: bytes
    content: bytes


@dataclass(frozen=True)
class FairExchangeAttestation:
    witness_id: str
    attestation_time: datetime
    released: bool
    party_a: RevealPayload
    party_b: RevealPayload
    signing_envelope: bytes
    witness_signature: bytes

    def __post_init__(self) -> None:
        """Enforce that each ``RevealPayload.content`` really is the
        preimage of its ``committed_hash``.

        Closes E3: the signed envelope binds only the DIDs and
        committed_hashes, so a tampered content field would verify green
        without this check. We refuse to even construct the dataclass
        with mismatched fields so downstream code can trust the
        ``content`` attribute.
        """
        for label, party in (("party_a", self.party_a), ("party_b", self.party_b)):
            expected = hashlib.sha256(party.nonce + party.content).digest()
            if expected != party.committed_hash:
                msg = f"{label}: committed_hash ≠ SHA-256(nonce || content)"
                raise ValueError(msg)

    def verify(self, witness_public_key: bytes) -> bool:
        expected = build_fair_exchange_envelope(
            self.witness_id,
            self.attestation_time,
            party_a_did=self.party_a.did,
            party_a_committed_hash=self.party_a.committed_hash.hex(),
            party_b_did=self.party_b.did,
            party_b_committed_hash=self.party_b.committed_hash.hex(),
            released=self.released,
        )
        if expected != self.signing_envelope:
            return False
        return ed25519_verify(witness_public_key, self.signing_envelope, self.witness_signature)


EphemeralAttestation = (
    LivenessRelayAttestation
    | VerifyAttestation
    | ArbitrationAttestation
    | RandomnessAttestation
    | QueryAttestation
    | FairExchangeAttestation
)


# ─── Helpers used by both sides ────────────────────────────────────


def sign_attestation(witness_private_key: bytes, envelope: bytes) -> bytes:
    """Sign a canonical envelope with the witness key."""
    return ed25519_sign(witness_private_key, envelope)


def verify_attestation(witness_public_key: bytes, envelope: bytes, signature: bytes) -> bool:
    """Verify a witness signature over a canonical envelope."""
    return ed25519_verify(witness_public_key, envelope, signature)


def vrf_random_from_signature(signature: bytes) -> bytes:
    """VRF output derivation: SHA-256(signature)."""
    return hashlib.sha256(signature).digest()
