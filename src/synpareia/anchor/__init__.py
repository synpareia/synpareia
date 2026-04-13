"""Anchor: cross-chain references between chains."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from synpareia.block import Block, create_block
from synpareia.types import AnchorType, BlockType

if TYPE_CHECKING:
    from synpareia.chain import Chain, ChainPosition
    from synpareia.identity import Profile


@dataclass(frozen=True)
class AnchorPayload:
    """Data carried by an anchor block: a reference to a position in another chain."""

    target_chain_id: str
    target_sequence: int
    target_block_hash: bytes  # content_hash of the block at that position
    anchor_type: AnchorType | str
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "target_chain_id": self.target_chain_id,
            "target_sequence": self.target_sequence,
            "target_block_hash": self.target_block_hash.hex(),
            "anchor_type": str(self.anchor_type),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> AnchorPayload:
        return cls(
            target_chain_id=str(data["target_chain_id"]),
            target_sequence=int(str(data["target_sequence"])),
            target_block_hash=bytes.fromhex(str(data["target_block_hash"])),
            anchor_type=str(data["anchor_type"]),
            metadata=data["metadata"] if isinstance(data.get("metadata"), dict) else {},  # type: ignore[arg-type]
        )


def create_anchor_block(
    profile: Profile,
    source_chain: Chain,
    *,
    target_chain_id: str,
    target_sequence: int,
    target_block_hash: bytes,
    anchor_type: AnchorType | str = AnchorType.CORRESPONDENCE,
    metadata: dict[str, object] | None = None,
) -> tuple[Block, ChainPosition]:
    """Create an anchor block and append it to the source chain.

    Returns (Block, ChainPosition).
    """
    payload = AnchorPayload(
        target_chain_id=target_chain_id,
        target_sequence=target_sequence,
        target_block_hash=target_block_hash,
        anchor_type=anchor_type,
        metadata=metadata or {},
    )

    content = json.dumps(payload.to_dict(), sort_keys=True).encode()

    block = create_block(
        profile,
        BlockType.ANCHOR,
        content,
        metadata={"anchor": payload.to_dict()},
    )

    position = source_chain.append(block)
    return block, position
