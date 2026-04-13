"""Storage protocol and in-memory implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from synpareia.block import Block
    from synpareia.chain import ChainPosition


@runtime_checkable
class ChainStore(Protocol):
    """Protocol for chain storage backends."""

    def store_block(self, chain_id: str, block: Block) -> None: ...
    def store_position(self, chain_id: str, position: ChainPosition) -> None: ...
    def get_block(self, block_id: str) -> Block | None: ...
    def get_position(self, chain_id: str, sequence: int) -> ChainPosition | None: ...
    def get_positions(self, chain_id: str, start: int, end: int | None) -> list[ChainPosition]: ...
    def get_block_by_chain_seq(self, chain_id: str, sequence: int) -> Block | None: ...
    def count(self, chain_id: str) -> int: ...
    def query_blocks(
        self,
        chain_id: str,
        *,
        block_type: str | None,
        author_id: str | None,
        limit: int,
    ) -> list[tuple[ChainPosition, Block]]: ...


class MemoryStore:
    """In-memory storage. Fast, ephemeral. Default for new chains."""

    def __init__(self) -> None:
        self._blocks: dict[str, Block] = {}  # block_id -> Block
        self._positions: dict[tuple[str, int], ChainPosition] = {}  # (chain_id, seq) -> pos
        self._chain_block_ids: dict[str, list[str]] = {}  # chain_id -> [block_id, ...]

    def store_block(self, chain_id: str, block: Block) -> None:
        self._blocks[block.id] = block
        self._chain_block_ids.setdefault(chain_id, []).append(block.id)

    def store_position(self, chain_id: str, position: ChainPosition) -> None:
        self._positions[(chain_id, position.sequence)] = position

    def get_block(self, block_id: str) -> Block | None:
        return self._blocks.get(block_id)

    def get_position(self, chain_id: str, sequence: int) -> ChainPosition | None:
        return self._positions.get((chain_id, sequence))

    def get_positions(self, chain_id: str, start: int, end: int | None) -> list[ChainPosition]:
        result: list[ChainPosition] = []
        seq = start
        while True:
            if end is not None and seq > end:
                break
            pos = self._positions.get((chain_id, seq))
            if pos is None:
                break
            result.append(pos)
            seq += 1
        return result

    def get_block_by_chain_seq(self, chain_id: str, sequence: int) -> Block | None:
        pos = self.get_position(chain_id, sequence)
        if pos is None:
            return None
        return self._blocks.get(pos.block_id)

    def count(self, chain_id: str) -> int:
        return sum(1 for k in self._positions if k[0] == chain_id)

    def query_blocks(
        self,
        chain_id: str,
        *,
        block_type: str | None,
        author_id: str | None,
        limit: int,
    ) -> list[tuple[ChainPosition, Block]]:
        results: list[tuple[ChainPosition, Block]] = []
        seq = 1
        while len(results) < limit:
            pos = self._positions.get((chain_id, seq))
            if pos is None:
                break
            block = self._blocks.get(pos.block_id)
            if block is not None:
                if block_type is not None and str(block.type) != block_type:
                    seq += 1
                    continue
                if author_id is not None and block.author_id != author_id:
                    seq += 1
                    continue
                results.append((pos, block))
            seq += 1
        return results
