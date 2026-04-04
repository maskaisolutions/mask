"""
Language Context Resolver — Unicode-block heuristic for multilingual DLP.

Examines the character distribution of an input buffer to infer the
dominant script / language.  The resolved language tag is consumed by
the ``DLPPatternRegistry`` to prioritise locale-specific regex groups
(e.g. Spanish addresses/honorifics).

Supported language tags:
  en — English (default / Latin-only fallback)
  es — Spanish
"""

from __future__ import annotations

import re
import logging
from typing import Dict

_log = logging.getLogger("mask.dlp.assessor")

# ── Unicode block classifiers ────────────────────────────────────────────────
# Each entry maps a language tag to a compiled regex that matches characters
# strongly indicative of that script.  Order matters: more specific blocks
# are checked first to avoid misclassification (e.g. ş/ğ/ı for Turkish
# before generic accented-Latin for French).

_SCRIPT_SIGNATURES: Dict[str, re.Pattern] = {
    # Spanish — ñ and inverted punctuation
    "es": re.compile(r"[ñÑ¡¿]"),
}


class LanguageContextResolver:
    """Determine the dominant language of a text buffer.

    The resolver is stateless and thread-safe.  Instantiate once and reuse
    for the lifetime of the process.

    Usage::

        resolver = LanguageContextResolver()
        tag = resolver.resolve("Hola, mi DNI es 12345678Z")
        # tag == "es"
    """

    # Minimum number of script-specific characters required before we
    # commit to a non-English tag. Lowered to 1 to catch single-character signatures
    # like a single 'ı' in 'Numarası'.
    CHAR_THRESHOLD = 1

    def resolve(self, text: str) -> str:
        """Return an ISO-639-1 language tag for *text*.

        Falls back to ``"en"`` when no distinctive script characters are
        found or the text is empty.
        """
        if not text:
            return "en"

        for tag, signature in _SCRIPT_SIGNATURES.items():
            hits = signature.findall(text)
            if len(hits) >= self.CHAR_THRESHOLD:
                _log.debug("Resolved language to '%s' (%d script chars)", tag, len(hits))
                return tag

        return "en"

    def resolve_with_detail(self, text: str) -> Dict[str, object]:
        """Return the language tag together with per-script hit counts.

        Useful for debugging and audit logging.
        """
        breakdown: Dict[str, int] = {}
        for tag, signature in _SCRIPT_SIGNATURES.items():
            count = len(signature.findall(text))
            if count:
                breakdown[tag] = count

        resolved = "en"
        for tag in _SCRIPT_SIGNATURES:
            if breakdown.get(tag, 0) >= self.CHAR_THRESHOLD:
                resolved = tag
                break

        return {"language": resolved, "breakdown": breakdown}
