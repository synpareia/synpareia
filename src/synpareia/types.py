"""Enums, type aliases, and constants for the synpareia SDK."""

from __future__ import annotations

from enum import StrEnum


class BlockType(StrEnum):
    MESSAGE = "message"
    THOUGHT = "thought"
    REACTION = "reaction"
    EDIT = "edit"
    RETRACTION = "retraction"
    JOIN = "join"
    LEAVE = "leave"
    SYSTEM = "system"
    COMMITMENT = "commitment"
    ANCHOR = "anchor"
    SEAL = "seal"
    STATE = "state"
    MEDIA = "media"


class ChainType(StrEnum):
    COP = "cop"
    SPHERE = "sphere"
    AUDIT = "audit"
    CUSTOM = "custom"


class AnchorType(StrEnum):
    CORRESPONDENCE = "correspondence"
    RECEIPT = "receipt"
    BRIDGE = "bridge"
    BRANCH = "branch"


class SealType(StrEnum):
    TIMESTAMP = "timestamp"
    STATE = "state"
    RECEIPT = "receipt"
    LIVENESS = "liveness"


class ContentMode(StrEnum):
    FULL = "full"
    HASH_ONLY = "hash_only"
    REVEALED = "revealed"


DID_PREFIX = "did:synpareia:"
