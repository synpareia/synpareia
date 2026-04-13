"""SQLite-backed persistent storage for chains."""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING

from synpareia.block import Block
from synpareia.chain import ChainPosition

if TYPE_CHECKING:
    from pathlib import Path


def _block_to_dict(block: Block) -> dict[str, object]:
    return {
        "id": block.id,
        "type": str(block.type),
        "author_id": block.author_id,
        "content_hash": block.content_hash.hex(),
        "created_at": block.created_at.isoformat(),
        "content": block.content.hex() if block.content is not None else None,
        "signature": block.signature.hex() if block.signature is not None else None,
        "metadata": block.metadata,
    }


def _dict_to_block(data: dict[str, object]) -> Block:
    from datetime import datetime

    content = bytes.fromhex(str(data["content"])) if data.get("content") else None
    signature = bytes.fromhex(str(data["signature"])) if data.get("signature") else None
    metadata = data.get("metadata")

    return Block(
        id=str(data["id"]),
        type=str(data["type"]),
        author_id=str(data["author_id"]),
        content_hash=bytes.fromhex(str(data["content_hash"])),
        created_at=datetime.fromisoformat(str(data["created_at"])),
        content=content,
        signature=signature,
        metadata=metadata if isinstance(metadata, dict) else {},
    )


def _pos_to_dict(pos: ChainPosition) -> dict[str, object]:
    return {
        "chain_id": pos.chain_id,
        "sequence": pos.sequence,
        "block_id": pos.block_id,
        "parent_hash": pos.parent_hash.hex() if pos.parent_hash else None,
        "position_hash": pos.position_hash.hex(),
    }


def _dict_to_pos(data: dict[str, object]) -> ChainPosition:
    parent_hash = bytes.fromhex(str(data["parent_hash"])) if data.get("parent_hash") else None
    return ChainPosition(
        chain_id=str(data["chain_id"]),
        sequence=int(str(data["sequence"])),
        block_id=str(data["block_id"]),
        parent_hash=parent_hash,
        position_hash=bytes.fromhex(str(data["position_hash"])),
    )


class SQLiteStore:
    """SQLite-backed persistent storage for chains."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path)
        self._init_tables()

    def _init_tables(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                id TEXT PRIMARY KEY,
                chain_id TEXT NOT NULL,
                data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_blocks_chain ON blocks(chain_id);

            CREATE TABLE IF NOT EXISTS positions (
                chain_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                block_id TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (chain_id, sequence)
            );
            """
        )
        self._conn.commit()

    def store_block(self, chain_id: str, block: Block) -> None:
        data = json.dumps(_block_to_dict(block))
        self._conn.execute(
            "INSERT OR REPLACE INTO blocks (id, chain_id, data) VALUES (?, ?, ?)",
            (block.id, chain_id, data),
        )
        self._conn.commit()

    def store_position(self, chain_id: str, position: ChainPosition) -> None:
        data = json.dumps(_pos_to_dict(position))
        self._conn.execute(
            "INSERT OR REPLACE INTO positions"
            " (chain_id, sequence, block_id, data) VALUES (?, ?, ?, ?)",
            (chain_id, position.sequence, position.block_id, data),
        )
        self._conn.commit()

    def get_block(self, block_id: str) -> Block | None:
        row = self._conn.execute("SELECT data FROM blocks WHERE id = ?", (block_id,)).fetchone()
        if row is None:
            return None
        return _dict_to_block(json.loads(row[0]))

    def get_position(self, chain_id: str, sequence: int) -> ChainPosition | None:
        row = self._conn.execute(
            "SELECT data FROM positions WHERE chain_id = ? AND sequence = ?",
            (chain_id, sequence),
        ).fetchone()
        if row is None:
            return None
        return _dict_to_pos(json.loads(row[0]))

    def get_positions(self, chain_id: str, start: int, end: int | None) -> list[ChainPosition]:
        if end is not None:
            rows = self._conn.execute(
                "SELECT data FROM positions WHERE chain_id = ?"
                " AND sequence >= ? AND sequence <= ? ORDER BY sequence",
                (chain_id, start, end),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM positions WHERE chain_id = ?"
                " AND sequence >= ? ORDER BY sequence",
                (chain_id, start),
            ).fetchall()
        return [_dict_to_pos(json.loads(row[0])) for row in rows]

    def get_block_by_chain_seq(self, chain_id: str, sequence: int) -> Block | None:
        pos = self.get_position(chain_id, sequence)
        if pos is None:
            return None
        return self.get_block(pos.block_id)

    def count(self, chain_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM positions WHERE chain_id = ?", (chain_id,)
        ).fetchone()
        return row[0] if row else 0

    def query_blocks(
        self,
        chain_id: str,
        *,
        block_type: str | None,
        author_id: str | None,
        limit: int,
    ) -> list[tuple[ChainPosition, Block]]:
        rows = self._conn.execute(
            "SELECT p.data, b.data FROM positions p JOIN blocks b ON p.block_id = b.id "
            "WHERE p.chain_id = ? ORDER BY p.sequence",
            (chain_id,),
        ).fetchall()

        results: list[tuple[ChainPosition, Block]] = []
        for pos_json, block_json in rows:
            if len(results) >= limit:
                break
            block = _dict_to_block(json.loads(block_json))
            if block_type is not None and str(block.type) != block_type:
                continue
            if author_id is not None and block.author_id != author_id:
                continue
            pos = _dict_to_pos(json.loads(pos_json))
            results.append((pos, block))
        return results

    def close(self) -> None:
        self._conn.close()
