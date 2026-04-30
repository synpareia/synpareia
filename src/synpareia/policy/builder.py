"""PolicyBuilder: fluent constructor for Policy dataclasses.

Useful for tests and for applications that want to assemble a policy
iteratively rather than pass a single dict of fields to `custom`.
"""

from __future__ import annotations

from typing import Self

from synpareia.policy.model import (
    AmendmentOverride,
    AmendmentRules,
    GdprMetadata,
    PerBlockRule,
    Policy,
    Retention,
    RetractorRule,
    RevealerRule,
    Signatory,
    WitnessDecl,
)
from synpareia.types import ChainType


class PolicyBuilder:
    """Fluent builder. Not thread-safe; intended for one-shot construction."""

    def __init__(self, chain_type: ChainType | str = ChainType.COP, version: str = "1") -> None:
        self._version = version
        self._chain_type = str(chain_type)
        self._signatories: list[Signatory] = []
        self._block_types_permitted: list[str] = []
        self._per_block_rules: list[PerBlockRule] = []
        self._witnesses: list[WitnessDecl] = []
        self._allowed_revealers: list[RevealerRule] = []
        self._allowed_retractors: list[RetractorRule] = []
        self._fork_permitted = False
        self._non_equivocation_enabled = False
        self._amendment_default = "all_signatories_cosign"
        self._amendment_overrides: list[AmendmentOverride] = []
        self._termination_rule = "soft_signal"
        self._activation_timeout_days = 1
        self._gdpr: GdprMetadata | None = None

    def signatory(self, did: str, role: str) -> Self:
        self._signatories.append(Signatory(did=did, role=role))
        return self

    def witness(
        self,
        did: str,
        roles: tuple[str, ...] = (),
        retention_days: int | None = None,
    ) -> Self:
        self._witnesses.append(WitnessDecl(did=did, roles=roles, retention_days=retention_days))
        return self

    def allow_block_type(self, block_type: str) -> Self:
        if block_type not in self._block_types_permitted:
            self._block_types_permitted.append(block_type)
        return self

    def rule(
        self,
        block_type: str,
        *,
        authors: tuple[str, ...] = (),
        signature_required: bool = True,
        receipt_required: bool = False,
        retention: Retention | None = None,
        seal_types: tuple[str, ...] = (),
    ) -> Self:
        self.allow_block_type(block_type)
        self._per_block_rules.append(
            PerBlockRule(
                block_type=block_type,
                authors=authors,
                signature_required=signature_required,
                receipt_required=receipt_required,
                retention=retention,
                seal_types=seal_types,
            )
        )
        return self

    def revealers(self, block_type: str, allowed: tuple[str, ...]) -> Self:
        self._allowed_revealers.append(RevealerRule(block_type=block_type, allowed=allowed))
        return self

    def retractors(self, block_type: str, allowed: tuple[str, ...]) -> Self:
        self._allowed_retractors.append(RetractorRule(block_type=block_type, allowed=allowed))
        return self

    def fork_permitted(self, value: bool = True) -> Self:
        self._fork_permitted = value
        return self

    def non_equivocation(self, value: bool = True) -> Self:
        self._non_equivocation_enabled = value
        return self

    def amendment_default(self, requirement: str) -> Self:
        self._amendment_default = requirement
        return self

    def amendment_rule(self, path: str, requirement: str) -> Self:
        self._amendment_overrides.append(AmendmentOverride(path=path, requirement=requirement))
        return self

    def termination_rule(self, rule: str) -> Self:
        self._termination_rule = rule
        return self

    def activation_timeout_days(self, days: int) -> Self:
        self._activation_timeout_days = days
        return self

    def gdpr(self, metadata: GdprMetadata) -> Self:
        self._gdpr = metadata
        return self

    def build(self) -> Policy:
        return Policy(
            version=self._version,
            chain_type=self._chain_type,
            signatories=tuple(self._signatories),
            block_types_permitted=tuple(self._block_types_permitted),
            per_block_rules=tuple(self._per_block_rules),
            witnesses=tuple(self._witnesses),
            allowed_revealers=tuple(self._allowed_revealers),
            allowed_retractors=tuple(self._allowed_retractors),
            fork_permitted=self._fork_permitted,
            non_equivocation_enabled=self._non_equivocation_enabled,
            amendment_rules=AmendmentRules(
                default=self._amendment_default,
                overrides=tuple(self._amendment_overrides),
            ),
            termination_rule=self._termination_rule,
            activation_timeout_days=self._activation_timeout_days,
            gdpr=self._gdpr,
        )
