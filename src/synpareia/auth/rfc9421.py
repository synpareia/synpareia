"""RFC 9421 HTTP Message Signatures — synpareia-shaped sign/verify wrapper.

Phase 1a of the funnel-implementation-roadmap. The Phase 1
``profiles_v2`` router authenticates publish/update/delete requests
via RFC 9421 HTTP Message Signatures with Ed25519. SDK consumers
(Phase 1f's ``synpareia.profile.publish``) sign requests with the
same primitive. This module is the shared sign + verify surface.

The implementation delegates spec-mechanics (Structured Field Values
parsing, signature-base derivation, header serialization) to the
``http-message-signatures`` library. The wrapper here:

- Pins Ed25519 as the only acceptable algorithm.
- Bakes in the synpareia default covered-component set:
  ``("@method", "@target-uri", "content-digest")``.
- Computes the ``Content-Digest`` header from the body bytes
  (SHA-256, RFC 9530), so callers don't need to know the digest spec.
- Enforces nonce + expiry parameters at sign time.
- Returns ``(valid, errors)`` from verification — errors carry a
  short structured ``code`` (``unknown_keyid``, ``expired``,
  ``signature_invalid``, etc.) so callers can produce stable HTTP
  error envelopes without parsing free-form messages.

Replay protection is the caller's responsibility: the verifier reports
the nonce in its result so the calling layer (the profiles_v2 router,
typically) can persist the seen-nonce set in storage of its choice.
The verifier also enforces ``created`` is within
``max_skew_seconds`` of now and that ``expires`` (if set by the
signer) hasn't passed.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from http_message_signatures import (  # type: ignore[attr-defined]
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    InvalidSignature,
)
from http_message_signatures.algorithms import ED25519  # type: ignore[attr-defined]

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "DEFAULT_COMPONENTS",
    "SignatureVerifyError",
    "SignedRequest",
    "sign_request",
    "verify_request",
]


DEFAULT_COMPONENTS: tuple[str, ...] = ("@method", "@target-uri", "content-digest")
"""Default RFC 9421 components synpareia signatures cover.

- ``@method`` and ``@target-uri`` bind the signature to the request
  method and full URL — preventing replay against a different path.
- ``content-digest`` binds the body via ``Content-Digest: sha-256=:...:``
  (RFC 9530) — preventing body tamper.
"""

_DEFAULT_LABEL = "sig"
"""The dictionary label both sides agree on. Callers don't usually
care about this — RFC 9421 supports multiple signatures with
different labels but synpareia's surface is single-signature."""

_DEFAULT_TAG = "synpareia"
"""Application-defined domain-separation tag included in every
synpareia-signed request. Verifiers reject signatures with a
different tag — preventing a signature minted for some other
application from being accepted on synpareia surfaces."""


@dataclass(frozen=True)
class SignedRequest:
    """Result of ``sign_request``: the headers a caller should add."""

    signature_input: str
    """Value for the ``Signature-Input`` HTTP header."""

    signature: str
    """Value for the ``Signature`` HTTP header."""

    content_digest: str
    """Value for the ``Content-Digest`` HTTP header.

    Always set, even for empty bodies, so verifiers can reject
    body-bearing requests that strip the header to avoid covering
    the body in the signature.
    """

    def headers(self) -> dict[str, str]:
        """Return all three headers as a dict ready for an HTTP client."""
        return {
            "Signature-Input": self.signature_input,
            "Signature": self.signature,
            "Content-Digest": self.content_digest,
        }


@dataclass(frozen=True)
class SignatureVerifyError:
    """Structured failure shape from ``verify_request``.

    ``code`` is one of a small fixed vocabulary so callers can map to
    HTTP error envelopes without string parsing.
    """

    code: str
    """One of ``missing_signature``, ``unknown_keyid``,
    ``malformed_signature``, ``missing_component``, ``expired``,
    ``stale``, ``signature_invalid``, ``content_digest_mismatch``,
    ``wrong_algorithm``."""

    detail: str
    """Human-readable detail; safe to log."""


@dataclass(frozen=True)
class _MessageView:
    """Minimal duck-typed message the http-message-signatures library
    accepts (it expects ``method``, ``url``, ``headers``)."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)


class _StaticKeyResolver(HTTPSignatureKeyResolver):
    """Single-key resolver for the signing path.

    The library wraps a private key in a resolver because RFC 9421
    supports key rotation per request via ``keyid``. On the signing
    side we always have one key; this resolver returns it
    unconditionally.
    """

    def __init__(self, *, key_id: str, private_key: bytes) -> None:
        self._key_id = key_id
        self._private_key_bytes = private_key

    def resolve_private_key(self, key_id: str) -> Any:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.from_private_bytes(self._private_key_bytes)

    def resolve_public_key(self, key_id: str) -> Any:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.from_private_bytes(self._private_key_bytes).public_key()


class _ResolverFromCallback(HTTPSignatureKeyResolver):
    """Verify-side resolver that delegates to a caller-supplied lookup.

    The lookup returns ``bytes | None``: 32 bytes of Ed25519 public
    key, or ``None`` if the keyid is unknown. The resolver's
    ``resolve_public_key`` raises ``KeyError`` on unknown — the
    library translates that into a verification failure.
    """

    def __init__(self, lookup: Callable[[str], bytes | None]) -> None:
        self._lookup = lookup

    def resolve_public_key(self, key_id: str) -> Any:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        raw = self._lookup(key_id)
        if raw is None:
            msg = f"unknown keyid: {key_id!r}"
            raise KeyError(msg)
        return Ed25519PublicKey.from_public_bytes(raw)

    def resolve_private_key(self, key_id: str) -> Any:  # pragma: no cover
        msg = "private key resolution unavailable on the verify path"
        raise NotImplementedError(msg)


def _content_digest(body: bytes) -> str:
    """Build the RFC 9530 ``Content-Digest`` header value over ``body``.

    Always SHA-256, encoded as a structured-fields dictionary with the
    ``sha-256`` member set to a base64-encoded byte sequence.
    """
    sha = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(sha).decode('ascii')}:"


def sign_request(
    *,
    method: str,
    target_uri: str,
    body: bytes = b"",
    private_key: bytes,
    keyid: str,
    extra_headers: dict[str, str] | None = None,
    expires_in_seconds: int = 60,
    nonce: str | None = None,
) -> SignedRequest:
    """Sign an HTTP request with Ed25519 per RFC 9421.

    Returns the ``Signature-Input``, ``Signature``, and
    ``Content-Digest`` headers the caller should add to their request.

    The covered components are fixed at ``DEFAULT_COMPONENTS``
    (``@method``, ``@target-uri``, ``content-digest``). The signature
    parameters always include ``created`` (= now), ``expires`` (= now
    + ``expires_in_seconds``), and a ``nonce``. If the caller does
    not supply one, ``sign_request`` mints a 128-bit cryptographically
    random nonce (``secrets.token_hex(16)``) — replay defence is
    on-by-default rather than opt-in (PT-003 footgun fix). Pass an
    explicit ``nonce`` only when the caller has its own determinism
    requirement.

    ``private_key`` is 32 bytes of raw Ed25519 private-key material.
    ``keyid`` is opaque to this module — usually a DID or a key
    fingerprint that the verifier-side resolver can map back to a
    public key.
    """
    if len(private_key) != 32:
        msg = f"sign_request: private_key must be 32 bytes, got {len(private_key)}"
        raise ValueError(msg)

    if nonce is None:
        nonce = secrets.token_hex(16)
    elif not nonce.strip():
        # Caller passed nonce="" or whitespace. Treating that as
        # "no nonce" would produce a signature ``verify_request``
        # rejects (require_nonce=True falsy-checks the parameter),
        # so the wrapper-to-wrapper round trip would silently fail.
        # Reject explicitly with a clearer message than the verifier
        # would surface.
        msg = "sign_request: nonce, if provided, must be non-empty (pass None to auto-generate)"
        raise ValueError(msg)

    digest = _content_digest(body)
    request_headers: dict[str, str] = {"Content-Digest": digest}
    if extra_headers:
        request_headers.update(extra_headers)

    message = _MessageView(method=method, url=target_uri, headers=request_headers)

    resolver = _StaticKeyResolver(key_id=keyid, private_key=private_key)
    signer = HTTPMessageSigner(signature_algorithm=ED25519, key_resolver=resolver)

    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=expires_in_seconds)

    signer.sign(
        message,
        key_id=keyid,
        created=now,
        expires=expires_at,
        nonce=nonce,
        label=_DEFAULT_LABEL,
        tag=_DEFAULT_TAG,
        covered_component_ids=DEFAULT_COMPONENTS,
    )

    return SignedRequest(
        signature_input=request_headers["Signature-Input"],
        signature=request_headers["Signature"],
        content_digest=digest,
    )


def verify_request(
    *,
    method: str,
    target_uri: str,
    headers: dict[str, str],
    body: bytes,
    public_key_resolver: Callable[[str], bytes | None],
    max_skew_seconds: int = 300,
    required_components: frozenset[str] = frozenset(DEFAULT_COMPONENTS),
    require_nonce: bool = True,
) -> tuple[bool, list[SignatureVerifyError]]:
    """Verify an HTTP request signed per RFC 9421.

    Returns ``(valid, errors)``. On failure, ``errors`` carries one or
    more ``SignatureVerifyError`` entries — each with a structured
    ``code`` (``missing_signature`` / ``unknown_keyid`` /
    ``content_digest_mismatch`` / ``expired`` / ``stale`` /
    ``missing_component`` / ``missing_nonce`` /
    ``signature_invalid`` / ``wrong_algorithm`` /
    ``malformed_signature``) and a free-text ``detail``.

    ``public_key_resolver(keyid)`` is invoked once per signature and
    returns 32 bytes of Ed25519 public-key material, or ``None`` to
    signal an unknown ``keyid`` (which the verifier maps to the
    ``unknown_keyid`` error code).

    The caller is responsible for nonce-tracking (deduplicating seen
    nonces in storage of its choice). The verifier enforces ``created``
    is within ``max_skew_seconds`` of "now" and that ``expires`` (if set
    on the signature) hasn't passed.

    ``require_nonce`` (default ``True``, PT-003 footgun fix) rejects
    signatures whose ``Signature-Input`` parameters omit ``nonce``. A
    signature without a nonce is replayable for the full
    ``max_skew_seconds`` window on any verifier that doesn't enforce
    one separately. Set ``False`` only when the caller has its own
    replay defence (e.g. a higher-level layer that pins a single-use
    token in the body).
    """
    errors: list[SignatureVerifyError] = []

    # The http-message-signatures library looks up headers with
    # canonical (mixed-case) names like "Signature-Input"; ASGI
    # frameworks (Starlette/FastAPI) normalise inbound headers to
    # lowercase before we get them. Callers may also send any other
    # casing — HTTP header names are case-insensitive (RFC 9110
    # §5.1). Re-canonicalise the well-known signature headers up
    # front so every subsequent presence/value check is
    # case-insensitive by construction, and the library finds the
    # headers it expects.
    canonical_aliases = {
        "signature-input": "Signature-Input",
        "signature": "Signature",
        "content-digest": "Content-Digest",
    }
    normalised_headers: dict[str, str] = {}
    for key, value in headers.items():
        normalised_headers[canonical_aliases.get(key.lower(), key)] = value

    # Pre-flight: the body's content-digest must match the header.
    # The library will reject a signature whose covered content-digest
    # value differs from the actual one, but a clearer error code
    # comes from comparing here first.
    actual_digest = _content_digest(body)
    header_digest = _lookup_header(normalised_headers, "Content-Digest")
    if header_digest is None:
        errors.append(
            SignatureVerifyError(
                code="missing_component",
                detail="Content-Digest header is missing; covered by default components",
            )
        )
        return False, errors
    if header_digest != actual_digest:
        errors.append(
            SignatureVerifyError(
                code="content_digest_mismatch",
                detail=(
                    f"Content-Digest header does not match SHA-256(body): "
                    f"header={header_digest!r}, computed={actual_digest!r}"
                ),
            )
        )
        return False, errors

    if _lookup_header(normalised_headers, "Signature") is None:
        errors.append(
            SignatureVerifyError(code="missing_signature", detail="Signature header is absent")
        )
        return False, errors
    if _lookup_header(normalised_headers, "Signature-Input") is None:
        errors.append(
            SignatureVerifyError(
                code="missing_signature", detail="Signature-Input header is absent"
            )
        )
        return False, errors

    message = _MessageView(method=method, url=target_uri, headers=normalised_headers)
    resolver = _ResolverFromCallback(public_key_resolver)

    verifier = HTTPMessageVerifier(signature_algorithm=ED25519, key_resolver=resolver)

    try:
        results = verifier.verify(
            message,
            max_age=timedelta(seconds=max_skew_seconds),
            expect_label=_DEFAULT_LABEL,
            expect_tag=_DEFAULT_TAG,
        )
    except InvalidSignature as exc:
        # Library raises this for: missing required component,
        # signature decoding errors, expired, stale, signature byte
        # mismatch, etc. The exception message is informative — pass
        # it through under a ``signature_invalid`` code.
        errors.append(SignatureVerifyError(code="signature_invalid", detail=str(exc) or repr(exc)))
        return False, errors
    except KeyError as exc:
        # Resolver raised KeyError for an unknown keyid.
        errors.append(SignatureVerifyError(code="unknown_keyid", detail=str(exc)))
        return False, errors
    except Exception as exc:  # noqa: BLE001 — defensive against library quirks
        errors.append(
            SignatureVerifyError(
                code="malformed_signature",
                detail=f"verification failed with unexpected error: {exc!r}",
            )
        )
        return False, errors

    if not results:
        errors.append(
            SignatureVerifyError(
                code="missing_signature",
                detail=f"no signature with label {_DEFAULT_LABEL!r} on the request",
            )
        )
        return False, errors

    # PT-003: reject signatures that omit ``nonce`` when require_nonce
    # is set (default). A signature without a nonce is replayable for
    # the full max_skew_seconds window on any verifier that doesn't
    # enforce one separately.
    if require_nonce:
        for result in results:
            params = result.parameters or {}
            if not params.get("nonce"):
                errors.append(
                    SignatureVerifyError(
                        code="missing_nonce",
                        detail=(
                            "signature parameters omit nonce; "
                            "require_nonce=True (default) rejects this"
                        ),
                    )
                )
                return False, errors

    # Cross-check that the algorithm parameter (if signed) is Ed25519.
    # The library's verifier won't pass for other algorithms because we
    # configured ED25519 only, but a clearer error helps.
    for result in results:
        alg = (result.parameters or {}).get("alg")
        if alg is not None and alg != ED25519.algorithm_id:
            errors.append(
                SignatureVerifyError(
                    code="wrong_algorithm",
                    detail=(
                        f"signature alg parameter is {alg!r}, expected {ED25519.algorithm_id!r}"
                    ),
                )
            )
            return False, errors

    # Enforce the signature's own ``expires`` parameter (if set by the
    # signer). The library's max_age check covers ``created`` freshness,
    # not signer-declared expiry — so a signer requesting a 1-second
    # validity window via ``expires_in_seconds=1`` would otherwise be
    # accepted up to ``max_skew_seconds`` later. We add the explicit
    # check so the signer's intent is honoured.
    now_unix = int(datetime.now(UTC).timestamp())
    for result in results:
        params = result.parameters or {}
        expires = params.get("expires")
        if expires is None:
            continue
        # The library may yield expires as int unix-seconds or datetime.
        if isinstance(expires, datetime):
            expires_unix = int(expires.timestamp())
        else:
            try:
                expires_unix = int(expires)
            except (TypeError, ValueError):
                continue
        if expires_unix < now_unix:
            errors.append(
                SignatureVerifyError(
                    code="expired",
                    detail=f"signature expired at {expires_unix} (now {now_unix})",
                )
            )
            return False, errors

    # Cross-check the covered components meet our minimum.
    for result in results:
        covered = {str(c).strip('"').lower() for c in (result.covered_components or {})}
        # The library returns components as quoted-name keys; strip and lowercase.
        # required_components are the well-known names already lowercase.
        missing = {c for c in required_components if c not in covered}
        if missing:
            errors.append(
                SignatureVerifyError(
                    code="missing_component",
                    detail=f"signature does not cover required components: {sorted(missing)!r}",
                )
            )
            return False, errors

    return True, errors


def _lookup_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    if name in headers:
        return headers[name]
    lower = name.lower()
    for key, value in headers.items():
        if key.lower() == lower:
            return value
    return None
