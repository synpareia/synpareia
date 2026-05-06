"""Authentication primitives for synpareia HTTP surfaces.

Currently exposes RFC 9421 HTTP Message Signatures helpers (Phase 1a
of the funnel-implementation-roadmap). The synpareia main service's
``profiles_v2`` router and the SDK's ``synpareia.profile.publish``
helper both verify / sign requests via this module.
"""

from __future__ import annotations

from synpareia.auth.rfc9421 import (
    DEFAULT_COMPONENTS,
    SignatureVerifyError,
    SignedRequest,
    sign_request,
    verify_request,
)

__all__ = [
    "DEFAULT_COMPONENTS",
    "SignatureVerifyError",
    "SignedRequest",
    "sign_request",
    "verify_request",
]
