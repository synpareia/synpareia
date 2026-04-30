"""Chain: ordered, append-only, hash-linked sequence of blocks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from synpareia.block import Block
    from synpareia.chain.storage import ChainStore
    from synpareia.policy.model import Policy
    from synpareia.types import ChainType, LifecycleState


@dataclass(frozen=True)
class ChainPosition:
    """A block's position within a chain."""

    chain_id: str
    sequence: int  # 1-indexed, monotonically increasing
    block_id: str
    parent_hash: bytes | None  # None for first position
    position_hash: bytes  # SHA-256 of position data


@dataclass
class Chain:
    """An ordered, append-only, hash-linked sequence of blocks."""

    id: str
    owner_id: str
    chain_type: ChainType | str
    created_at: datetime
    head_hash: bytes | None  # hash of latest position (None when empty)
    metadata: dict[str, object]
    _store: ChainStore
    policy_hash: bytes | None = field(default=None)

    def append(self, block: Block) -> ChainPosition:
        from synpareia.chain.operations import append_block

        return append_block(self, block)

    def verify(
        self,
        *,
        public_keys: dict[str, bytes] | None = None,
    ) -> tuple[bool, list[str]]:
        from synpareia.chain.operations import verify_chain

        return verify_chain(self, public_keys=public_keys)

    def get_position(self, sequence: int) -> ChainPosition | None:
        return self._store.get_position(self.id, sequence)

    def get_block(self, sequence: int) -> Block | None:
        return self._store.get_block_by_chain_seq(self.id, sequence)

    def get_positions(self, start: int = 1, end: int | None = None) -> list[ChainPosition]:
        return self._store.get_positions(self.id, start, end)

    def query(
        self,
        *,
        block_type: str | None = None,
        author_id: str | None = None,
        limit: int = 50,
    ) -> list[tuple[ChainPosition, Block]]:
        return self._store.query_blocks(
            self.id, block_type=block_type, author_id=author_id, limit=limit
        )

    @property
    def length(self) -> int:
        return self._store.count(self.id)

    @property
    def head(self) -> ChainPosition | None:
        length = self.length
        if length == 0:
            return None
        return self._store.get_position(self.id, length)

    @property
    def policy(self) -> Policy | None:
        """Parse the POLICY block at position 1; None if missing or malformed."""
        from synpareia.policy.lifecycle import extract_policy

        return extract_policy(self)

    @property
    def state(self) -> LifecycleState:
        """Current lifecycle state (Proposed / Pending / Active / Concluded)."""
        from synpareia.policy.lifecycle import compute_lifecycle_state

        return compute_lifecycle_state(self)
