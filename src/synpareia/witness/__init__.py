"""Witness client — Tier 4 network operations.

Requires the 'witness' optional dependency: pip install synpareia[witness]
for the network client. Ephemeral attestation dataclasses and offline
verifiers are always importable.
"""

from __future__ import annotations

from synpareia.witness.ephemeral import (
    ArbitrationAttestation,
    EphemeralAttestation,
    FairExchangeAttestation,
    LivenessRelayAttestation,
    QueryAttestation,
    RandomnessAttestation,
    RevealPayload,
    VerifyAttestation,
)

_CLIENT_EXPORTS: list[str] = []

try:
    from synpareia.witness.client import (
        SyncWitnessClient,  # noqa: F401 — re-exported via __all__
        WitnessClient,  # noqa: F401
        WitnessInfo,  # noqa: F401
    )

    _CLIENT_EXPORTS = ["SyncWitnessClient", "WitnessClient", "WitnessInfo"]
except ImportError:
    # httpx not installed — ephemeral dataclasses still usable offline
    pass

__all__ = [
    "ArbitrationAttestation",
    "EphemeralAttestation",
    "FairExchangeAttestation",
    "LivenessRelayAttestation",
    "QueryAttestation",
    "RandomnessAttestation",
    "RevealPayload",
    "VerifyAttestation",
    *_CLIENT_EXPORTS,
]
