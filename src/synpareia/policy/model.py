"""Policy data model: frozen dataclasses describing a chain's consent vehicle.

See docs/explorations/chain-policy-primitive.md §9 for the canonical
field catalogue. All collections are tuples so Policy remains hashable
and deep-immutable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Signatory:
    did: str
    role: str


@dataclass(frozen=True)
class WitnessDecl:
    did: str
    roles: tuple[str, ...] = ()
    retention_days: int | None = None


@dataclass(frozen=True)
class Retention:
    mode: str  # "indefinite" | "bounded" | "ephemeral"
    duration_days: int | None = None


@dataclass(frozen=True)
class PerBlockRule:
    block_type: str
    authors: tuple[str, ...] = ()
    signature_required: bool = True
    receipt_required: bool = False
    retention: Retention | None = None
    seal_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class RevealerRule:
    block_type: str
    allowed: tuple[str, ...]


@dataclass(frozen=True)
class RetractorRule:
    block_type: str
    allowed: tuple[str, ...]


@dataclass(frozen=True)
class AmendmentOverride:
    path: str
    requirement: str


@dataclass(frozen=True)
class AmendmentRules:
    default: str = "all_signatories_cosign"
    overrides: tuple[AmendmentOverride, ...] = ()

    def __post_init__(self) -> None:
        # Canonicalise override order so equality survives JCS round-trips.
        sorted_overrides = tuple(sorted(self.overrides, key=lambda o: o.path))
        if sorted_overrides != self.overrides:
            object.__setattr__(self, "overrides", sorted_overrides)

    def requirement_for(self, path: str) -> str:
        for override in self.overrides:
            if override.path == path:
                return override.requirement
        return self.default


@dataclass(frozen=True)
class GdprMetadata:
    controller_did: str | None = None
    purpose: str | None = None
    lawful_basis: str | None = None
    retention_days: int | None = None
    subject_rights_contact: str | None = None


@dataclass(frozen=True)
class Policy:
    version: str
    chain_type: str
    signatories: tuple[Signatory, ...]
    block_types_permitted: tuple[str, ...]
    per_block_rules: tuple[PerBlockRule, ...] = ()
    witnesses: tuple[WitnessDecl, ...] = ()
    allowed_revealers: tuple[RevealerRule, ...] = ()
    allowed_retractors: tuple[RetractorRule, ...] = ()
    fork_permitted: bool = False
    non_equivocation_enabled: bool = False
    amendment_rules: AmendmentRules = field(default_factory=AmendmentRules)
    termination_rule: str = "soft_signal"
    activation_timeout_days: int = 1
    gdpr: GdprMetadata | None = None

    @property
    def signatory_dids(self) -> tuple[str, ...]:
        return tuple(s.did for s in self.signatories)

    @property
    def witness_dids(self) -> tuple[str, ...]:
        return tuple(w.did for w in self.witnesses)

    def is_signatory(self, did: str) -> bool:
        return did in self.signatory_dids

    def is_witness(self, did: str) -> bool:
        return did in self.witness_dids
