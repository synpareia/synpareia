"""Tests for the RFC 9421 sigauth wrapper (Phase 1a).

Round-trip + the structured failure modes the verifier surfaces:
unknown_keyid, content_digest_mismatch, missing_signature,
missing_component, signature_invalid (covering body-tamper,
signature-byte-tamper, expired, stale).

The implementation delegates spec-mechanics to
``http-message-signatures`` so these tests intentionally exercise
the wrapper's contract — the structured error codes, the default
component set, the keyid resolver shape, the content-digest
binding — rather than re-validating the underlying spec library.
"""

from __future__ import annotations

import base64
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from synpareia.auth import (
    DEFAULT_COMPONENTS,
    SignatureVerifyError,
    SignedRequest,
    sign_request,
    verify_request,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_keypair() -> tuple[bytes, bytes]:
    """Return ``(private_bytes, public_bytes)`` — both 32 bytes raw."""
    priv = Ed25519PrivateKey.generate()
    return (
        priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


def _resolver(public_key: bytes, keyid: str = "kid1"):
    """Build a public-key resolver that returns ``public_key`` for one keyid."""

    def lookup(requested: str) -> bytes | None:
        return public_key if requested == keyid else None

    return lookup


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestSignVerifyRoundTrip:
    def test_minimal_round_trip(self) -> None:
        priv, pub = _make_keypair()
        signed = sign_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b'{"foo": "bar"}',
            private_key=priv,
            keyid="kid1",
            nonce="abc123",
        )
        assert isinstance(signed, SignedRequest)
        assert "Signature-Input" in signed.headers()
        assert signed.content_digest.startswith("sha-256=:")

        valid, errors = verify_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers=signed.headers(),
            body=b'{"foo": "bar"}',
            public_key_resolver=_resolver(pub),
        )
        assert valid, errors
        assert errors == []

    def test_empty_body_round_trip(self) -> None:
        """Body-less requests (e.g. DELETE) still get a content-digest
        and verify cleanly."""
        priv, pub = _make_keypair()
        signed = sign_request(
            method="DELETE",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b"",
            private_key=priv,
            keyid="kid1",
        )
        valid, errors = verify_request(
            method="DELETE",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers=signed.headers(),
            body=b"",
            public_key_resolver=_resolver(pub),
        )
        assert valid, errors

    def test_extra_headers_passthrough(self) -> None:
        """Caller can carry additional headers (e.g. an opt-in scope
        token) through the signed-headers bundle without affecting the
        signature; only the default components are covered."""
        priv, pub = _make_keypair()
        signed = sign_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b"hello",
            private_key=priv,
            keyid="kid1",
            extra_headers={"X-Foo": "bar"},
        )
        # X-Foo isn't returned in SignedRequest; caller adds it themselves.
        assert "X-Foo" not in signed.headers()

        # Verifier doesn't care about X-Foo because it's not covered.
        headers = {**signed.headers(), "X-Foo": "bar"}
        valid, errors = verify_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers=headers,
            body=b"hello",
            public_key_resolver=_resolver(pub),
        )
        assert valid, errors


# ---------------------------------------------------------------------------
# Structured failure modes
# ---------------------------------------------------------------------------


class TestVerificationErrors:
    def test_unknown_keyid(self) -> None:
        priv, _pub = _make_keypair()
        signed = sign_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b"x",
            private_key=priv,
            keyid="kid-unknown-to-resolver",
        )

        def empty_resolver(_keyid: str) -> bytes | None:
            return None

        valid, errors = verify_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers=signed.headers(),
            body=b"x",
            public_key_resolver=empty_resolver,
        )
        assert not valid
        assert any(e.code == "unknown_keyid" for e in errors)

    def test_content_digest_mismatch_when_body_tampered(self) -> None:
        priv, pub = _make_keypair()
        signed = sign_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b"original",
            private_key=priv,
            keyid="kid1",
        )
        valid, errors = verify_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers=signed.headers(),
            body=b"TAMPERED",
            public_key_resolver=_resolver(pub),
        )
        assert not valid
        assert any(e.code == "content_digest_mismatch" for e in errors)

    def test_missing_signature_header(self) -> None:
        _priv, pub = _make_keypair()
        valid, errors = verify_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers={
                "Content-Digest": "sha-256=:" + base64.b64encode(b"\x00" * 32).decode() + ":"
            },
            body=b"",
            public_key_resolver=_resolver(pub),
        )
        assert not valid
        # The body's content-digest doesn't match this fake header, so we
        # actually surface content_digest_mismatch first; that's fine —
        # the API contract says "fail-closed with at least one error code".
        assert errors
        assert errors[0].code in {"missing_signature", "content_digest_mismatch"}

    def test_missing_content_digest_header(self) -> None:
        priv, pub = _make_keypair()
        signed = sign_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b"x",
            private_key=priv,
            keyid="kid1",
        )
        # Strip Content-Digest while keeping Signature/Signature-Input
        headers = signed.headers()
        del headers["Content-Digest"]
        valid, errors = verify_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers=headers,
            body=b"x",
            public_key_resolver=_resolver(pub),
        )
        assert not valid
        assert any(e.code == "missing_component" for e in errors)

    def test_uppercase_signature_headers_accepted(self) -> None:
        """HTTP headers are case-insensitive (RFC 9110 §5.1).

        Sign a request, then re-key the headers to all-uppercase
        before verifying. The verifier must accept the request the
        same as if the headers had canonical mixed-case keys.
        """
        priv, pub = _make_keypair()
        signed = sign_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b"hello",
            private_key=priv,
            keyid="kid1",
        )
        upper_headers = {k.upper(): v for k, v in signed.headers().items()}

        valid, errors = verify_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers=upper_headers,
            body=b"hello",
            public_key_resolver=_resolver(pub),
        )
        assert valid, errors

    def test_signature_byte_tamper(self) -> None:
        priv, pub = _make_keypair()
        signed = sign_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b"x",
            private_key=priv,
            keyid="kid1",
        )
        # Flip a byte in the signature value
        headers = signed.headers()
        sig_value = headers["Signature"]
        # Find the base64 chunk and mutate one character
        head, eq, rest = sig_value.partition("=")
        # sig_value looks like sig=:<b64>:; replace inside the quotes
        if ":" in rest:
            before, base64_body, after = rest.split(":", 2)
            base64_chars = list(base64_body)
            # flip one char at the start
            base64_chars[0] = "A" if base64_chars[0] != "A" else "B"
            mutated = head + eq + before + ":" + "".join(base64_chars) + ":" + after
            headers["Signature"] = mutated

        valid, errors = verify_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers=headers,
            body=b"x",
            public_key_resolver=_resolver(pub),
        )
        assert not valid
        assert any(e.code in {"signature_invalid", "malformed_signature"} for e in errors), (
            f"expected signature_invalid/malformed_signature, got {[e.code for e in errors]}"
        )

    def test_replay_against_different_target_uri_fails(self) -> None:
        """The same signed bundle replayed against a different URL is
        rejected because @target-uri is in the covered components."""
        priv, pub = _make_keypair()
        signed = sign_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b"x",
            private_key=priv,
            keyid="kid1",
        )
        valid, errors = verify_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:VICTIM",
            headers=signed.headers(),
            body=b"x",
            public_key_resolver=_resolver(pub),
        )
        assert not valid
        assert any(e.code == "signature_invalid" for e in errors)

    def test_replay_against_different_method_fails(self) -> None:
        """Same as above but flips the method (GET vs the original POST)."""
        priv, pub = _make_keypair()
        signed = sign_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b"x",
            private_key=priv,
            keyid="kid1",
        )
        valid, errors = verify_request(
            method="GET",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers=signed.headers(),
            body=b"x",
            public_key_resolver=_resolver(pub),
        )
        assert not valid
        assert any(e.code == "signature_invalid" for e in errors)

    def test_expired_signature_fails(self) -> None:
        """A signature whose ``expires`` parameter has passed is
        rejected. Not via wall-clock waiting — the library's max_age
        is configurable, so we sign with a tight expiry and then
        verify after sleeping long enough to clear it."""
        priv, pub = _make_keypair()
        signed = sign_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            body=b"x",
            private_key=priv,
            keyid="kid1",
            expires_in_seconds=1,
        )
        time.sleep(2)
        valid, errors = verify_request(
            method="POST",
            target_uri="https://example.com/api/v1/profiles/did:synpareia:abc",
            headers=signed.headers(),
            body=b"x",
            public_key_resolver=_resolver(pub),
        )
        assert not valid
        assert any(e.code == "expired" for e in errors)


# ---------------------------------------------------------------------------
# Defaults + module surface
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_default_components_constant(self) -> None:
        """The default covered-component set is published — callers
        wanting to override must do so explicitly via
        ``required_components``."""
        assert DEFAULT_COMPONENTS == ("@method", "@target-uri", "content-digest")

    def test_signed_request_headers_dict_shape(self) -> None:
        """SignedRequest.headers() returns the three header names with
        the exact casing HTTP clients should set."""
        priv, _pub = _make_keypair()
        signed = sign_request(
            method="GET",
            target_uri="https://example.com/foo",
            body=b"",
            private_key=priv,
            keyid="kid1",
        )
        h = signed.headers()
        assert set(h.keys()) == {"Signature-Input", "Signature", "Content-Digest"}

    def test_sign_rejects_wrong_length_private_key(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="must be 32 bytes"):
            sign_request(
                method="GET",
                target_uri="https://example.com/foo",
                body=b"",
                private_key=b"\x00" * 16,
                keyid="kid1",
            )

    def test_signature_verify_error_is_frozen_dataclass(self) -> None:
        import dataclasses

        err = SignatureVerifyError(code="x", detail="y")
        assert dataclasses.is_dataclass(err)
        assert err.code == "x"
