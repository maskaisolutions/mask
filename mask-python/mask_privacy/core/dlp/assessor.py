"""
Language Context Resolver — Unicode-block heuristic for multilingual DLP.

Examines the character distribution of an input buffer to infer the
dominant script / language.  The resolved language tag is consumed by
the ``DLPPatternRegistry`` to prioritise locale-specific regex groups
(e.g. Turkish honorifics, Arabic address keywords).

Supported language tags:
  en — English (default / Latin-only fallback)
  es — Spanish
  fr — French
  de — German
  tr — Turkish
  ar — Arabic
  zh — Chinese (Simplified / Traditional)
  ja — Japanese
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
    # CJK / East-Asian — checked first because they are unambiguous
    "zh": re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]"),
    "ja": re.compile(r"[\u3040-\u309f\u30a0-\u30ff\u31f0-\u31ff]"),

    # Arabic script — covers Standard Arabic, Urdu overlap, etc.
    "ar": re.compile(r"[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff\ufb50-\ufdff\ufe70-\ufeff]"),

    # Turkish — distinguished by dotless-i (ı), soft-g (ğ), ş, and cedilla ç
    # We look for specifically Turkish letters that do NOT appear in French/German.
    "tr": re.compile(r"[ğıİşŞ]"),

    # German — umlauts and Eszett
    "de": re.compile(r"[äöüÄÖÜß]"),

    # Spanish — ñ and inverted punctuation
    "es": re.compile(r"[ñÑ¡¿]"),

    # French — cedilla, accented vowels with circumflex / diaeresis
    "fr": re.compile(r"[àâçéèêëïîôùûüÿœæ]", re.IGNORECASE),
}


class LanguageContextResolver:
    """Determine the dominant language of a text buffer.

    The resolver is stateless and thread-safe.  Instantiate once and reuse
    for the lifetime of the process.

    Usage::

        resolver = LanguageContextResolver()
        tag = resolver.resolve("Merhaba, TC Kimlik Numaram 12345678901")
        # tag == "tr"
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
