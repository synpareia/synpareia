"""Topology layer — pairwise directional edges between DIDs.

**Experimental (0.6.0):** published for the event-submission conventions
(tag schema, milli-units, channel mapper) that the live ingest endpoint
needs; no stability promise. The aggregate's semantics are expected to
change pending the aggregation visibility review (the module stays
namespace-scoped — nothing here is exported from the top-level
``synpareia`` package).

v0 in-memory implementation. See ``docs/explorations/topology-layer.md`` for the
design spec. Production substrate (directory-service DB integration + witness-side
event hooks + MCP tool exposure) lands as separate work informed by dojo runs.

Public surface:

- :class:`EdgePair` — the one-record-per-pair data model
- :class:`TopologyStore` — in-memory edge ledger with update + read methods
- :func:`shortest_path` — BFS shortest-path between two DIDs
- :func:`path_familiarity` — min-along-path familiarity aggregator
"""

from __future__ import annotations

from synpareia.topology.aggregate import (
    DEFAULT_ALPHA,
    DEFAULT_MAX_HOPS,
    SummaryStat,
    aggregate_reputation,
    combine,
    summary_statistic,
    transitive_author_weights,
)
from synpareia.topology.algorithms import path_familiarity, path_strength, shortest_path
from synpareia.topology.ledger import Contribution, ContributionLedger
from synpareia.topology.model import (
    DEFAULT_VISIBILITY,
    INTERACTION_CHANNEL,
    THIRD_PARTY_VISIBLE,
    VALENCE_CHANNEL,
    VISIBILITY_BILATERAL,
    VISIBILITY_NETWORK_TRAVERSABLE,
    EdgePair,
    Moment,
    is_symmetric,
    ordered_pair_key,
)
from synpareia.topology.readtime import (
    NEGATIVE_VALENCE_WEIGHT,
    clamp_valence,
    negative_valence_value,
)
from synpareia.topology.store import EdgeView, TopologyStore
from synpareia.topology.tags import (
    SUPPORTED_TAG_VERSIONS,
    TagMappedEvent,
    TagValidationError,
    map_tags,
    validate_tags,
)

__all__ = [
    "DEFAULT_ALPHA",
    "DEFAULT_MAX_HOPS",
    "DEFAULT_VISIBILITY",
    "INTERACTION_CHANNEL",
    "NEGATIVE_VALENCE_WEIGHT",
    "SUPPORTED_TAG_VERSIONS",
    "THIRD_PARTY_VISIBLE",
    "VALENCE_CHANNEL",
    "VISIBILITY_BILATERAL",
    "VISIBILITY_NETWORK_TRAVERSABLE",
    "Contribution",
    "ContributionLedger",
    "EdgePair",
    "EdgeView",
    "Moment",
    "SummaryStat",
    "TagMappedEvent",
    "TagValidationError",
    "TopologyStore",
    "aggregate_reputation",
    "clamp_valence",
    "combine",
    "is_symmetric",
    "map_tags",
    "negative_valence_value",
    "ordered_pair_key",
    "path_familiarity",
    "path_strength",
    "shortest_path",
    "summary_statistic",
    "transitive_author_weights",
    "validate_tags",
]
