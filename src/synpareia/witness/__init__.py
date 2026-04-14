"""Witness client — Tier 4 network operations.

Requires the 'witness' optional dependency: pip install synpareia[witness]
"""

from __future__ import annotations

try:
    from synpareia.witness.client import SyncWitnessClient, WitnessClient, WitnessInfo

    __all__ = ["SyncWitnessClient", "WitnessClient", "WitnessInfo"]
except ImportError:
    # httpx not installed
    pass
