"""``synpareia.profile`` — agent-card construction and directory client.

Phase 1f of the funnel-implementation-roadmap. SDK-side surface for
the profile-directory routes that landed in Phase 1d/1e. The split
mirrors the design doc:

**Local helpers** (no network, stdlib + cryptography only):

- ``build_agent_card(profile, **fields) -> AgentCard``: assemble an
  ``AgentCard`` dataclass from a ``synpareia.identity.Profile`` plus
  optional A2A and synpareia-extension fields.
- ``card_canonical_bytes(card) -> bytes``: JCS-canonicalise the card
  to the bytes the operator signs and the directory verifies.
- ``sign_agent_card(card_bytes, private_key) -> bytes``: Ed25519
  signature over the canonical bytes.
- ``verify_agent_card(card_bytes, signature, public_key) -> bool``:
  offline verification.

**Network helpers** (require ``httpx``, available via the
``synpareia[profile]`` extra):

- ``ProfileClient.publish(...)`` — POST envelope + RFC 9421 sigauth
- ``ProfileClient.get_existence(...)`` — GET fixed-shape view
- ``ProfileClient.get_history(...)`` — GET cursor-paginated history
- ``ProfileClient.get_well_known(...)`` — GET A2A discovery surface
- ``ProfileClient.delete_history_version(...)`` — sigauth'd tombstone
- ``ProfileClient.delete_profile(...)`` — sigauth'd full delete
- ``ProfileClient.request_witness_anchor(...)`` — hash-only seal request

Sync wrapper ``SyncProfileClient`` follows the same pattern as
``SyncWitnessClient`` for callers in non-async contexts.
"""

from __future__ import annotations

from synpareia.profile.card import (
    A2AAuthentication,
    A2ACapabilities,
    AgentCard,
    FirstContactFee,
    PersistenceOptIn,
    SynpareiaExtensions,
    WellKnownPublicationPolicy,
    build_agent_card,
    card_canonical_bytes,
    sign_agent_card,
    verify_agent_card,
)

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

# The network client requires httpx; expose it only when the optional
# dependency is installed so the module's local-helper surface
# remains importable in environments that don't ship httpx.
try:
    from synpareia.profile.client import ProfileClient, SyncProfileClient  # noqa: F401

    __all__ += ["ProfileClient", "SyncProfileClient"]
except ImportError:  # pragma: no cover — httpx not installed
    pass
