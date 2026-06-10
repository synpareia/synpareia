"""Read-time projection policy for topology edges (Slice 2).

The stored accumulators are kept **raw and linear** (design rule 3,
``docs/explorations/topology-erasure-design.md`` §9): a clean additive sum, so
contribution-subtract erasure recovers exactly the edge that would exist had an
event never happened. All nonlinearity — clamping (here) and decay (a later
slice) — is applied at *read* time, on top of the raw sum. This module holds
that read-time policy.

Two concerns live here:

- **Valence clamp.** Served valence is clamped to ``[-1, 1]`` (the spec range,
  ``topology-layer.md`` §2.3 / ``topology-production-design.md`` §2). Familiarity
  is *not* clamped — it is a monotonic cumulative co-occurrence weight with no
  ceiling. The clamp is read-only; it never touches the stored value.

- **Negative-signal weighting.** Witnessed-negative events (a forfeit, a
  ``kept:false / made_good_faith_attempt:false`` Promise resolution, a
  negative-experience Claim) contribute a *larger-magnitude* valence delta than
  the positive equivalents, because the soft-gossip channel systematically
  under-supplies negatives (``topology-production-design.md`` §3, RepuNet #4).
  The ratio ``δ_negative : δ_positive`` is the ratified ``NEGATIVE_VALENCE_WEIGHT``
  (1.5×). This is a *linear write-time scaling of the event delta* — it scales
  the magnitude before the delta is accumulated, so the stored sum stays linear
  and erasure (subtract the same scaled delta) remains exact.

  Placement note: the *classification* of an event as witnessed-negative lives in
  the event→delta mapping (the directory/Form layer, a later slice), not in the
  ``TopologyStore`` primitive — the store takes a raw ``(w, v)`` pair and cannot
  tell a "negative event" from "a small negative correction." So the SDK exposes
  the constant and ``negative_valence_value`` helper; the mapping layer calls it.

  Two-moment note: the 1.5× scales the *value* ``v`` (decision 2026-06-08), not
  the backing weight ``w`` — a negative event lands at a more-negative ``v`` while
  ``w`` stays the honest interaction weight, so confidence (``Σw``) is unbiased
  and only the magnitude (``Σw·v / Σw``) reflects the asymmetry.
"""

from __future__ import annotations

import math

# Spec valence range (topology-layer.md §2.3). Familiarity has no ceiling.
VALENCE_MIN: float = -1.0
VALENCE_MAX: float = 1.0

# Ratified δ_negative : δ_positive asymmetry (topology-production-design.md §3).
NEGATIVE_VALENCE_WEIGHT: float = 1.5


def clamp_valence(raw: float) -> float:
    """Clamp a raw accumulated valence to the served range ``[-1, 1]``.

    Read-time only — the stored accumulator stays unclamped/linear so that
    contribution-subtract erasure is exact (design rule 3).

    ``±inf`` clamp to the bounds (they are extreme-but-ordered values with a
    well-defined clamp target). ``NaN`` is rejected: it is unordered, so it would
    otherwise fall through both comparisons and be returned *outside* the promised
    served range — silently propagating corruption. The store's write-time guard
    (``update_valence`` rejects non-finite deltas) means a stored value is never
    NaN; this guard is defense-in-depth for direct callers of the public helper,
    keeping the module's stance uniform (non-finite valence is rejected loudly at
    every entry point)."""
    if math.isnan(raw):
        raise ValueError("clamp_valence received NaN; valence must be a real number")
    if raw < VALENCE_MIN:
        return VALENCE_MIN
    if raw > VALENCE_MAX:
        return VALENCE_MAX
    return raw


def negative_valence_value(magnitude: float) -> float:
    """Map a witnessed-negative event's base ``magnitude`` (≥ 0) to the signed,
    weighted valence **value** ``v``: ``-magnitude * NEGATIVE_VALENCE_WEIGHT``.

    The result is the value ``v`` to record for the event; the accumulator adds
    ``Moment(sw=w, swv=w·v)`` for the event's weight ``w``, so the 1.5× lands on
    the magnitude (via ``Σw·v``) while ``w`` (the backing/confidence) is unscaled.
    Linear, so the contribution is exactly subtractable on erasure. Called by the
    event→delta mapping layer once it has *classified* an event as
    witnessed-negative; the ``TopologyStore`` itself stays value-agnostic. The
    scaled ``v`` may fall outside ``[-1, 1]`` at the accumulator level — that is
    fine; the served magnitude is clamped read-time by ``clamp_valence``.

    ``magnitude`` must be finite and non-negative. Non-finite input (``NaN``,
    ``±inf``) is rejected here so the produced value is always safe to accumulate;
    failing at the helper makes the misuse immediate rather than one call later."""
    if not math.isfinite(magnitude) or magnitude < 0:
        raise ValueError(
            f"negative_valence_value takes a finite non-negative base magnitude; got {magnitude}"
        )
    return -magnitude * NEGATIVE_VALENCE_WEIGHT
