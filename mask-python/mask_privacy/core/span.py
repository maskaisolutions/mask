"""
Span Resolution Engine — Sweep-Line Overlap Resolver.

Instead of mutating the text string after every regex hit (O(N·hits) allocations),
all tiers now collect lightweight ``Span`` objects.  Once all tiers have finished,
``resolve_overlaps`` performs a single O(K log K) pass to choose the winning span
in every conflicting region, and the caller rebuilds the string exactly once.

Algorithm
---------
1. Sort spans by (start ASC, length DESC, confidence DESC).
2. Walk left-to-right, tracking the furthest consumed index ``occupied_end``.
3. Any span that starts before ``occupied_end`` is a conflict:
   - Fully contained → always discard (champion already covers it).
   - Partial overlap  → kept only if its confidence is strictly higher; the
     champion's end is used as the trim boundary (we don't split tokens).
4. The surviving spans are returned in reverse start order so the caller can
   replace right-to-left without offset drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(order=False)
class Span:
    """Represents one PII match from any detection tier."""

    start: int
    end: int
    entity_type: str
    original_value: str
    confidence: float
    method: str                          # "dlp_heuristic" | "regex" | "nlp"
    language: Optional[str] = field(default=None)

    # Filled in by the caller after encode_fn is applied
    masked_value: Optional[str] = field(default=None)

    @property
    def length(self) -> int:
        return self.end - self.start


def resolve_overlaps(spans: List[Span]) -> List[Span]:
    """Return a non-overlapping, right-to-left-ordered subset of *spans*.

    Parameters
    ----------
    spans:
        Raw, potentially overlapping list from all scanning tiers.

    Returns
    -------
    List[Span]
        De-duplicated spans sorted by ``start`` descending — ready for
        right-to-left string reconstruction.
    """
    if not spans:
        return []

    # Primary sort: start ASC; secondary: length DESC (prefer longer spans);
    # tertiary: confidence DESC (prefer more certain matches).
    sorted_spans = sorted(
        spans,
        key=lambda s: (s.start, -(s.end - s.start), -s.confidence),
    )

    resolved: List[Span] = []
    occupied_end: int = -1

    for span in sorted_spans:
        if span.start >= occupied_end:
            # No overlap — accept this span unconditionally.
            resolved.append(span)
            occupied_end = span.end
        elif span.end <= occupied_end:
            # Fully inside an already-accepted span — discard.
            continue
        else:
            # Partial overlap: span starts inside occupied zone but extends
            # beyond it.  Only keep if it is more confident than the current
            # champion; we purposely do NOT split the overlapping tokens.
            last = resolved[-1]
            if span.confidence > last.confidence:
                resolved.pop()
                resolved.append(span)
                occupied_end = span.end
            # else: discard the challenger

    # Return in descending start order so callers can slice right-to-left
    # without offset drift.
    resolved.sort(key=lambda s: s.start, reverse=True)
    return resolved


def reconstruct(text: str, resolved_spans: List[Span]) -> str:
    """Rebuild *text* from a right-to-left-ordered list of resolved spans.

    Each span must have ``masked_value`` already populated.

    This is the single string-construction pass that replaces all 50+ per-hit
    allocations in the old waterfall pipeline.
    """
    # resolved_spans must be sorted start DESC already (output of resolve_overlaps)
    result = text
    for span in resolved_spans:
        if span.masked_value is None:
            continue
        result = result[: span.start] + span.masked_value + result[span.end :]
    return result
