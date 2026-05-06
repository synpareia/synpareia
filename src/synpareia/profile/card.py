"""AgentCard dataclasses + local sign/verify (no network).

The wire shape mirrors the main service's pydantic ``AgentCard``
schema (``src/synpareia/schemas/agent_card.py``) but uses plain
dataclasses to keep the SDK pydantic-free. The dictionary produced
by ``card.to_dict()`` is exactly what the directory parses on the
publish path.

**Identity layer is mandatory.** ``id`` (the canonical DID) and
``public_key_b64`` are always present and must agree:
``id == "did:synpareia:" + sha256(public_key).hex()``. The
directory rejects publishes that don't satisfy this binding;
``build_agent_card`` constructs a card that does so by default.

**Synpareia extensions live under** ``extensions["synpareia"]`` in
the canonical wire shape. The ``SynpareiaExtensions`` dataclass is
serialised under that key by ``card.to_dict()``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from synpareia.hash import jcs_canonicalize
from synpareia.identity import Profile  # noqa: TC001 — runtime function-arg annotation

__all__ = [
    "A2AAuthentication",
    "A2ACapabilities",
    "AgentCard",
    "FirstContactFee",
    "PersistenceOptIn",
    "SynpareiaExtensions",
    "WellKnownPublicationPolicy",
    "build_agent_card",
    "card_canonical_bytes",
    "sign_agent_card",
    "verify_agent_card",
]


# ---------------------------------------------------------------------------
# Synpareia-extension dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class A2ACapabilities:
    """A2A v1.2 capabilities block. Conservative defaults — operators
    opt in to streaming or push notifications by setting these to True.
    """

    streaming: bool = False
    push_notifications: bool = False
    """Wire-name override: serialised as ``pushNotifications`` (camelCase)
    per the A2A spec; we keep snake_case in Python."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "streaming": self.streaming,
            "pushNotifications": self.push_notifications,
        }


@dataclass(frozen=True)
class A2AAuthentication:
    """A2A v1.2 authentication declaration. ``schemes`` is the set of
    auth schemes the operator accepts on direct A2A traffic; the
    default (empty) declares no authenticated A2A surface beyond the
    well-known card itself.
    """

    schemes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"schemes": list(self.schemes)}


@dataclass(frozen=True)
class FirstContactFee:
    """First-contact fee a sender pays the network to address a
    direct-approach request to this profile. Credits flow to the
    platform's revenue pool, not the recipient (sellers don't pay)."""

    credits: int

    def to_dict(self) -> dict[str, Any]:
        return {"credits": self.credits}


@dataclass(frozen=True)
class PersistenceOptIn:
    """Operator-declared opt-in to non-erasure persistence.

    ``opted_in_at`` is an ISO-8601 timestamp. ``scope`` is a list of
    ``"card_history"`` / ``"key_chain"`` / ``"reputation"`` — each
    name flagging a category of data the operator commits to keep
    persistent until the opt-in is withdrawn.
    """

    opted_in_at: str
    scope: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"opted_in_at": self.opted_in_at, "scope": list(self.scope)}


@dataclass(frozen=True)
class WellKnownPublicationPolicy:
    """Operator-declared policy for ``GET /agents/{did}/.well-known/agent-card.json``.

    Controls which A2A *standard* fields surface at the well-known
    endpoint. Identity-layer and rules-of-engagement fields are
    public-always; reputation is never served at well-known. See
    ``services.well_known`` in the main service for the full
    visibility contract.

    **Three states the operator can express:**

    1. **No policy block at all** — pass ``well_known_publication=None``
       to ``build_agent_card`` (the default). The directory uses
       ``DEFAULT_WELL_KNOWN_A2A_STANDARD_FIELDS`` (``name``,
       ``description``, ``version``).
    2. **Explicit allow-list** — pass
       ``WellKnownPublicationPolicy(a2a_standard_fields=["name", "skills", ...])``.
       The directory publishes only the listed fields.
    3. **Explicit opt-out** — pass
       ``WellKnownPublicationPolicy(a2a_standard_fields=[])``
       (or the bare ``WellKnownPublicationPolicy()`` constructor,
       which defaults the list to empty). The directory serves
       only the synpareia identity layer + rules-of-engagement,
       suppressing every optional A2A field.

    The bare ``WellKnownPublicationPolicy()`` is **not** "use defaults"
    — it's the explicit opt-out. To get defaults, omit the policy
    block entirely.
    """

    a2a_standard_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"a2a_standard_fields": list(self.a2a_standard_fields)}


@dataclass(frozen=True)
class SynpareiaExtensions:
    """Synpareia-namespaced extension fields; lives at
    ``extensions["synpareia"]`` in the canonical wire shape."""

    schema_version: str = "1.0"
    role_tag: str | None = None
    first_contact_fee: FirstContactFee | None = None
    persistence: PersistenceOptIn | None = None
    accepted_payment_rails: list[str] = field(default_factory=list)
    well_known_publication: WellKnownPublicationPolicy | None = None
    """Optional well-known publication policy. Serialised under
    ``policies.well_known_publication`` in the wire shape."""

    model_family: str | None = None
    domain_expertise: list[str] | None = None
    reasoning_style: dict[str, Any] | None = None
    """Free-form structured reasoning-style declaration."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema_version": self.schema_version,
            "accepted_payment_rails": list(self.accepted_payment_rails),
        }
        if self.role_tag is not None:
            out["role_tag"] = self.role_tag
        if self.first_contact_fee is not None:
            out["first_contact_fee"] = self.first_contact_fee.to_dict()
        if self.persistence is not None:
            out["persistence"] = self.persistence.to_dict()
        if self.well_known_publication is not None:
            out["policies"] = {"well_known_publication": self.well_known_publication.to_dict()}
        if self.model_family is not None:
            out["model_family"] = self.model_family
        if self.domain_expertise is not None:
            out["domain_expertise"] = list(self.domain_expertise)
        if self.reasoning_style is not None:
            out["reasoning_style"] = dict(self.reasoning_style)
        return out


# ---------------------------------------------------------------------------
# AgentCard
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentCard:
    """A2A v1.2-compatible agent card with synpareia extensions.

    The canonical signed bytes are the JCS canonicalisation of
    ``self.to_dict()``. Operators sign those bytes with their
    Ed25519 private key and publish the
    ``(card_bytes, signature, public_key_b64)`` triple to the
    directory.
    """

    # Identity layer (required by the directory).
    id: str
    """Canonical DID — must equal
    ``did:synpareia:`` + sha256(public_key).hex(). The directory
    enforces this binding on publish."""

    public_key_b64: str
    """Operator's Ed25519 public key, base64-encoded."""

    # A2A standard fields. Default-empty so a minimal card is just
    # identity layer; operators opt into richer A2A discovery.
    name: str = ""
    description: str | None = None
    provider: str | None = None
    url: str | None = None
    version: str = "1.0"
    skills: list[str] = field(default_factory=list)
    capabilities: A2ACapabilities = field(default_factory=A2ACapabilities)
    """A2A v1.2 capabilities block. Conservative defaults
    (``streaming=False``, ``push_notifications=False``) — operators
    opt in via ``build_agent_card(capabilities=A2ACapabilities(...))``."""

    authentication: A2AAuthentication = field(default_factory=A2AAuthentication)
    """A2A v1.2 authentication declaration. Default empty; operators
    declare schemes by passing ``authentication=A2AAuthentication(schemes=[...])``."""

    synpareia: SynpareiaExtensions = field(default_factory=SynpareiaExtensions)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "public_key_b64": self.public_key_b64,
            "skills": list(self.skills),
            "capabilities": self.capabilities.to_dict(),
            "authentication": self.authentication.to_dict(),
            "extensions": {"synpareia": self.synpareia.to_dict()},
        }
        if self.description is not None:
            out["description"] = self.description
        if self.provider is not None:
            out["provider"] = self.provider
        if self.url is not None:
            out["url"] = self.url
        return out


# ---------------------------------------------------------------------------
# Builders + sign/verify
# ---------------------------------------------------------------------------


def build_agent_card(
    profile: Profile,
    *,
    name: str = "",
    description: str | None = None,
    provider: str | None = None,
    url: str | None = None,
    version: str = "1.0",
    skills: list[str] | None = None,
    capabilities: A2ACapabilities | None = None,
    authentication: A2AAuthentication | None = None,
    role_tag: str | None = None,
    first_contact_fee: FirstContactFee | None = None,
    persistence: PersistenceOptIn | None = None,
    accepted_payment_rails: list[str] | None = None,
    well_known_publication: WellKnownPublicationPolicy | None = None,
    model_family: str | None = None,
    domain_expertise: list[str] | None = None,
    reasoning_style: dict[str, Any] | None = None,
) -> AgentCard:
    """Assemble an ``AgentCard`` from a ``Profile`` plus optional fields.

    The DID and ``public_key_b64`` are derived **from
    ``profile.public_key``** so the identity-layer binding holds by
    construction — the directory's publish gate enforces the same
    binding, so a card built by this function is guaranteed to
    pass that check before it leaves the SDK.

    Raises ``ValueError`` if ``profile.id`` disagrees with the DID
    derived from ``profile.public_key``. Without this check a caller
    could hand-construct an inconsistent ``Profile`` (the dataclass
    is public) and the directory would silently reject the publish
    later — better to fail at construction.
    """
    import hashlib

    derived_did = "did:synpareia:" + hashlib.sha256(profile.public_key).hexdigest()
    if profile.id != derived_did:
        msg = (
            f"profile.id {profile.id!r} disagrees with did derived from "
            f"profile.public_key ({derived_did!r}); refusing to build a card "
            "whose identity-layer binding the directory will reject"
        )
        raise ValueError(msg)

    pub_b64 = base64.b64encode(profile.public_key).decode("ascii")
    syn = SynpareiaExtensions(
        role_tag=role_tag,
        first_contact_fee=first_contact_fee,
        persistence=persistence,
        accepted_payment_rails=accepted_payment_rails or [],
        well_known_publication=well_known_publication,
        model_family=model_family,
        domain_expertise=domain_expertise,
        reasoning_style=reasoning_style,
    )
    return AgentCard(
        id=derived_did,
        public_key_b64=pub_b64,
        name=name,
        description=description,
        provider=provider,
        url=url,
        version=version,
        skills=skills or [],
        capabilities=capabilities or A2ACapabilities(),
        authentication=authentication or A2AAuthentication(),
        synpareia=syn,
    )


def card_canonical_bytes(card: AgentCard) -> bytes:
    """Return the JCS-canonical bytes the operator signs.

    Identical to what the directory recomputes on the verify path —
    ``hash(canonical_bytes)`` is the seal target for witness
    anchoring and the input to ``sign_agent_card``.
    """
    return jcs_canonicalize(card.to_dict())


def sign_agent_card(card_bytes: bytes, private_key: bytes) -> bytes:
    """Sign canonical card bytes with Ed25519.

    ``private_key`` is 32 bytes raw. Returns the 64-byte signature.
    Raises ``ValueError`` if the key isn't 32 bytes.
    """
    if len(private_key) != 32:
        msg = f"private_key must be 32 bytes, got {len(private_key)}"
        raise ValueError(msg)
    return Ed25519PrivateKey.from_private_bytes(private_key).sign(card_bytes)


def verify_agent_card(card_bytes: bytes, signature: bytes, public_key: bytes) -> bool:
    """Offline verification of a signed card.

    Returns False on any failure (wrong-length key, invalid
    signature, malformed input). Never raises — callers can rely
    on a boolean.
    """
    if len(public_key) != 32:
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(public_key)
        pk.verify(signature, card_bytes)
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 — defensive against malformed input
        return False
    return True
