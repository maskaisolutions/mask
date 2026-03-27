"""
DLP Confidence Scorer — Proximity-weighted scoring for sensitive data matches.

Combines three independent signals into a single confidence value for each
candidate match, determining whether the JIT encryption hook should fire:

1. **Base risk** — intrinsic leakage probability of the data type.
2. **Proximity boost** — logarithmic-decay bonus for each context keyword
   found near the match within a configurable window.
3. **Validator override** — hard-validator pass forces confidence to 0.99.

The scorer is stateless and thread-safe.
"""

from __future__ import annotations

import math
import logging
from typing import FrozenSet, Optional

_log = logging.getLogger("mask.dlp.scorer")


class DLPConfidenceScorer:
    """Calculate a weighted confidence score for a single regex hit.

    Scoring formula::

        proximity_bonus = Σ  KEYWORD_BOOST / (1 + ln(1 + distance_i))
        raw_score       = base_risk + proximity_bonus
        final_score     = min(MAX_CONFIDENCE, raw_score)

    If a hard-validator returns ``True``, ``final_score`` is overridden
    to ``VALIDATOR_OVERRIDE``.

    Parameters
    ----------
    context_window : int
        Number of characters on each side of the match to scan for keywords.
    keyword_boost : float
        Maximum bonus per keyword (applied at distance = 0).
    validator_override : float
        Confidence assigned when a hard-validator passes.
    max_confidence : float
        Upper clamp for any computed score.
    penalty_factor : float
        Multiplier applied when a hard-validator *fails*.
    """

    DEFAULTS = dict(
        context_window=100,
        keyword_boost=0.10,
        validator_override=0.99,
        max_confidence=0.99,
        penalty_factor=0.65,
    )

    def __init__(self, **overrides) -> None:
        cfg = {**self.DEFAULTS, **overrides}
        self._window: int = cfg["context_window"]
        self._kw_boost: float = cfg["keyword_boost"]
        self._val_override: float = cfg["validator_override"]
        self._ceil: float = cfg["max_confidence"]
        self._penalty: float = cfg["penalty_factor"]

    # ── public API ────────────────────────────────────────────────────────

    def score(
        self,
        *,
        base_risk: float,
        match_start: int,
        match_end: int,
        full_text: str,
        proximity_terms: FrozenSet[str],
        validator_passed: Optional[bool],
    ) -> float:
        """Compute the final confidence for one candidate match.

        Parameters
        ----------
        base_risk
            Intrinsic leakage probability from the pattern descriptor.
        match_start / match_end
            Character offsets of the regex hit inside *full_text*.
        full_text
            The complete input buffer (needed for the context window).
        proximity_terms
            Lowercased keywords to search for near the match.
        validator_passed
            Result from ``DLPValidationEngine.run()``:
            ``True`` → override, ``False`` → penalty, ``None`` → no effect.

        Returns
        -------
        float
            Confidence in ``[0.0, max_confidence]``.
        """
        # Hard-validator short-circuits
        if validator_passed is True:
            return self._val_override
        if validator_passed is False:
            return min(self._ceil, base_risk * self._penalty)

        # Extract the context window around the match
        window_lo = max(0, match_start - self._window)
        window_hi = min(len(full_text), match_end + self._window)
        context_slice = full_text[window_lo:window_hi].lower()

        # Accumulate proximity bonuses
        proximity_bonus = 0.0
        match_mid = (match_start + match_end) / 2.0

        for term in proximity_terms:
            search_pos = 0
            while True:
                idx = context_slice.find(term, search_pos)
                if idx == -1:
                    break
                # Translate window-relative index back to absolute offset
                abs_pos = window_lo + idx
                distance = abs(abs_pos - match_mid)
                bonus = self._kw_boost / (1.0 + math.log(1.0 + distance))
                proximity_bonus += bonus
                search_pos = idx + len(term)

        raw = base_risk + proximity_bonus
        return min(self._ceil, raw)
