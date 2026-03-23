"""
Entity Detection Scanner — Tiered Waterfall Pipeline.

Scans unstructured text to identify PII (Emails, Phones, SSNs, Credit Cards,
Names) and replaces them in-place with Format-Preserving Encryption (FPE)
tokens so that the LLM only sees tokenised shapes, never the raw PII.

Detection Architecture (Waterfall):
  Tier 1 — Deterministic: Regex + Checksum  (fast, provable, auditable)
  Tier 2 — Probabilistic: Presidio NLP       (slow, fuzzy, catches names)

Tier 1 matches are excised from the text buffer *before* Tier 2 runs,
ensuring the NLP engine never wastes compute on already-masked entities
and cannot produce contradictory results.
"""

import os
import re
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Optional, List, Dict, Callable

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
except ImportError:
    raise ImportError(
        "Presidio packages are required. Install with: "
        "pip install presidio-analyzer presidio-anonymizer"
    )

from mask_privacy.core.vault import encode
from mask_privacy.core.fpe import generate_fpe_token, looks_like_token

logger = logging.getLogger("mask.scanner")

# Persistent thread pool for NLP analysis to avoid per-call thread churn
_SCANNER_POOL = ThreadPoolExecutor(max_workers=int(os.environ.get("MASK_NLP_MAX_WORKERS", "4")))

# Regex patterns for Tier 1 deterministic detection

REGEX_PATTERNS: Dict[str, re.Pattern] = {
    "EMAIL_ADDRESS": re.compile(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    ),
    "PHONE_NUMBER": re.compile(
        r"\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}"
        r"|\d{3}[\s\-.]?\d{4}"
    ),
    # International phone numbers (UK +44, France +33, Germany +49)
    "PHONE_NUMBER_INTL": re.compile(
        r"\+(?:44|33|49)[\s\-.]?\(?\d{1,5}\)?(?:[\s\-.]?\d{2,4}){2,4}"
    ),
    "US_SSN": re.compile(r"\d{3}-\d{2}-\d{4}"),
    "CREDIT_CARD": re.compile(r"(?:\d{4}[ \-]?){3}\d{4}"),
    # US ABA Routing/Transit Number (9 digits, validated via checksum in Tier 1)
    "US_ROUTING_NUMBER": re.compile(r"\b\d{9}\b"),
    # US Passport: 1 letter followed by 8 digits
    "US_PASSPORT": re.compile(r"\b[A-Z]\d{8}\b"),
    # Date-of-birth patterns: MM/DD/YYYY and YYYY-MM-DD
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b"
        r"|\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"
    ),
}

# Keywords whose mere presence in the context/prompt boosts detection
# aggressiveness for nearby digit strings.
CONTEXT_KEYWORDS = frozenset([
    "account number", "ssn", "phone", "credit card",
    "iban", "bank", "email", "pii", "personal info",
])


# Scanner class

class PresidioScanner:
    """Tiered Waterfall scanner for PII detection.

    Tier 1 (Deterministic) runs Regex + Luhn checksums.
    Tier 2 (Probabilistic) runs Presidio NLP on the *remaining* text.
    """

    def __init__(self) -> None:
        import spacy
        available_models = [
            m for m in ("en_core_web_lg", "en_core_web_md", "en_core_web_sm")
            if spacy.util.is_package(m)
        ]
        if not available_models:
            raise ImportError(
                "Mask: Missing AI Model. To enable PII protection, please run: "
                'pip install "mask-privacy[sm]" (Small) or pip install "mask-privacy[lg]" (Large).'
            )
        selected_model = available_models[0]
        logger.info("Using spaCy model: %s", selected_model)

        from presidio_analyzer.nlp_engine import NlpEngineProvider
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": selected_model}],
        })
        nlp_engine = provider.create_engine()

        self._analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine, supported_languages=["en"]
        )
        self._anonymizer = AnonymizerEngine()
        self._supported_entities = [
            "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD",
            "US_BANK_NUMBER", "CRYPTO", "IBAN_CODE", "IP_ADDRESS", "PERSON",
        ]

    def set_supported_entities(self, entities: List[str]) -> None:
        """Replace the entity detection list."""
        self._supported_entities = list(entities)
        logger.info("Scanner entities updated: %s", self._supported_entities)

    # Tier 1 — Deterministic detection
    @staticmethod
    def _luhn_checksum(cc_number: str) -> bool:
        """Validate a credit card number using the Luhn algorithm."""
        digits = [int(d) for d in re.sub(r"\D", "", cc_number)]
        odd = digits[-1::-2]
        even = digits[-2::-2]
        total = sum(odd) + sum(
            sum(divmod(d * 2, 10)) for d in even
        )
        return total % 10 == 0

    @staticmethod
    def _aba_checksum(routing_number: str) -> bool:
        """Validate a US ABA routing number using the checksum algorithm."""
        d = [int(c) for c in routing_number]
        if len(d) != 9:
            return False
        checksum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
        return checksum % 10 == 0

    def _tier1_regex(
        self,
        text: str,
        encode_fn: Callable[[str], str],
        boost_entities: frozenset,
        aggressive: bool,
        confidence_threshold: float,
    ) -> tuple[str, List[Dict]]:
        """Run Regex patterns + Luhn checksum, excise matches from text."""
        entities: List[Dict] = []
        excised = text

        # Sort matches by start position (descending) so replacements
        # don't shift earlier offsets.
        all_matches: list[tuple[int, int, str, str, float]] = []

        for entity_type, pattern in REGEX_PATTERNS.items():
            for m in pattern.finditer(text):
                confidence = 0.95
                if aggressive or entity_type.lower().replace("_", " ") in boost_entities:
                    confidence = 1.0
                # Boost credit cards that pass Luhn
                if entity_type == "CREDIT_CARD" and self._luhn_checksum(m.group(0)):
                    confidence = max(confidence, 0.99)
                # Validate ABA routing numbers via checksum — drop non-matching
                if entity_type == "US_ROUTING_NUMBER" and not self._aba_checksum(m.group(0)):
                    continue
                all_matches.append((m.start(), m.end(), entity_type, m.group(0), confidence))

        # Deduplicate overlapping spans — keep the longest match
        all_matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        filtered: list[tuple[int, int, str, str, float]] = []
        last_end = -1
        for start, end, etype, val, conf in all_matches:
            if start >= last_end:
                filtered.append((start, end, etype, val, conf))
                last_end = end

        # Replace from right to left to preserve offsets
        for start, end, etype, val, conf in reversed(filtered):
            if conf >= confidence_threshold and not looks_like_token(val):
                token = encode_fn(val)
                excised = excised[:start] + token + excised[end:]
                entities.append({
                    "type": etype,
                    "value": val,
                    "method": "regex",
                    "confidence": conf,
                    "masked_value": token,
                })

        return excised, entities

    # Tier 2 — Probabilistic NLP detection

    def _tier2_nlp(
        self,
        text: str,
        encode_fn: Callable[[str], str],
        boost_entities: frozenset,
        aggressive: bool,
        confidence_threshold: float,
    ) -> tuple[str, List[Dict]]:
        """Run Presidio NLP on text that has already been excised of Tier 1 matches.

        Enforces a configurable timeout (``MASK_NLP_TIMEOUT_SECONDS``, default 30).
        Raises ``MaskNLPTimeout`` if the Presidio analysis exceeds the deadline.
        """
        from mask_privacy.core.exceptions import MaskNLPTimeout

        timeout = float(os.environ.get("MASK_NLP_TIMEOUT_SECONDS", "60"))

        entities: List[Dict] = []

        # Run the heavy NLP analysis with a timeout guard
        future = _SCANNER_POOL.submit(
            self._analyzer.analyze,
            text=text, entities=self._supported_entities, language="en",
        )
        try:
            results = future.result(timeout=timeout)
        except FuturesTimeoutError:
            raise MaskNLPTimeout(
                f"Presidio analysis exceeded {timeout}s timeout"
            )

        masked_text = text
        # Sort by start descending for safe replacement
        results.sort(key=lambda r: r.start, reverse=True)
        for r in results:
            confidence = r.score if hasattr(r, "score") else 0.7
            if aggressive or r.entity_type.lower().replace("_", " ") in boost_entities:
                confidence = min(1.0, confidence + 0.2)

            val = text[r.start:r.end]
            if confidence >= confidence_threshold and not looks_like_token(val):
                token = encode_fn(val)
                masked_text = masked_text[:r.start] + token + masked_text[r.end:]
                entities.append({
                    "type": r.entity_type,
                    "value": val,
                    "method": "nlp",
                    "confidence": confidence,
                    "masked_value": token,
                })

        return masked_text, entities

    # Public API

    def _resolve_boost(self, context: Optional[str]) -> frozenset:
        """Determine which entity types should get a confidence boost."""
        if not context:
            return frozenset()
        lowered = context.lower()
        return frozenset(kw for kw in CONTEXT_KEYWORDS if kw in lowered)

    def scan_and_tokenize(
        self,
        text: str,
        encode_fn: Optional[Callable[[str], str]] = None,
        pipeline: Optional[List[str]] = None,
        confidence_threshold: float = 0.7,
        context: Optional[str] = None,
        aggressive: bool = False,
    ) -> str:
        """Scan text and replace PII using the tiered Waterfall pipeline.

        Args:
            text: Input text to scan.
            encode_fn: Optional custom encoding function (defaults to vault.encode).
            pipeline: Detection tiers to run (``["regex", "checksum", "nlp"]``).
            confidence_threshold: Minimum confidence to mask an entity.
            context: Optional prompt/context string used to boost detection.
            aggressive: If True, boost confidence for all matches.

        Returns:
            The text with PII replaced by FPE tokens.
        """
        if not text or not isinstance(text, str):
            return text

        pipeline = pipeline or ["regex", "checksum", "nlp"]
        _encode = encode_fn or encode
        boost = self._resolve_boost(context)

        # --- Tier 1: Deterministic ---
        if "regex" in pipeline or "checksum" in pipeline:
            text, _ = self._tier1_regex(text, _encode, boost, aggressive, confidence_threshold)

        # --- Tier 2: Probabilistic (on the *remaining* text) ---
        if "nlp" in pipeline:
            text, _ = self._tier2_nlp(text, _encode, boost, aggressive, confidence_threshold)

        return text

    def scan_and_return_entities(
        self,
        text: str,
        encode_fn: Optional[Callable[[str], str]] = None,
        pipeline: Optional[List[str]] = None,
        confidence_threshold: float = 0.7,
        context: Optional[str] = None,
        aggressive: bool = False,
    ) -> List[Dict]:
        """Detect PII entities and return metadata (type, value, confidence)."""
        if not text or not isinstance(text, str):
            return []

        pipeline = pipeline or ["regex", "checksum", "nlp"]
        _encode = encode_fn or encode
        boost = self._resolve_boost(context)
        all_entities: List[Dict] = []

        remaining = text

        if "regex" in pipeline or "checksum" in pipeline:
            remaining, tier1 = self._tier1_regex(remaining, _encode, boost, aggressive, confidence_threshold)
            all_entities.extend(tier1)

        if "nlp" in pipeline:
            _, tier2 = self._tier2_nlp(remaining, _encode, boost, aggressive, confidence_threshold)
            all_entities.extend(tier2)

        return all_entities

    async def ascan_and_tokenize(
        self,
        text: str,
        encode_fn: Optional[Callable[[str], str]] = None,
        pipeline: Optional[List[str]] = None,
        confidence_threshold: float = 0.7,
        context: Optional[str] = None,
        aggressive: bool = False,
    ) -> str:
        """Async wrapper for ``scan_and_tokenize``."""
        import asyncio
        return await asyncio.to_thread(
            self.scan_and_tokenize,
            text, encode_fn, pipeline, confidence_threshold, context, aggressive
        )


class RemotePresidioScanner(PresidioScanner):
    """Scanner that calls a remote Presidio Analyzer endpoint.

    This avoids loading the ~500MB spaCy model into the application process.
    Requires ``httpx`` to be installed.

    NOTE: This is intended for future "Hosted" or "Enterprise" deployments 
    where NLP compute is offloaded to a centralized service.
    """

    def __init__(self, endpoint_url: str) -> None:
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "The 'httpx' package is required for RemotePresidioScanner. "
                "Install it with: pip install httpx"
            )
        self.endpoint_url = endpoint_url
        self._httpx = httpx
        logger.info("Using RemotePresidioScanner at %s", endpoint_url)

    def _tier2_nlp(
        self,
        text: str,
        encode_fn: Callable[[str], str],
        boost_entities: frozenset,
        aggressive: bool,
        confidence_threshold: float,
    ) -> tuple[str, List[Dict]]:
        entities: List[Dict] = []
        try:
            resp = self._httpx.post(
                self.endpoint_url,
                json={"text": text, "language": "en"}
            )
            resp.raise_for_status()
            results = resp.json()
        except Exception as e:
            logger.error("Remote NLP scan failed: %s", e)
            return text, []

        masked_text = text
        # Assuming the standard Presidio API schema
        results.sort(key=lambda r: r.get("start", 0), reverse=True)
        for r in results:
            start, end, entity_type = r["start"], r["end"], r["entity_type"]
            confidence = r.get("score", 0.7)
            if aggressive or entity_type.lower().replace("_", " ") in boost_entities:
                confidence = min(1.0, confidence + 0.2)

            val = text[start:end]
            if confidence >= confidence_threshold and not looks_like_token(val):
                token = encode_fn(val)
                masked_text = masked_text[:start] + token + masked_text[end:]
                entities.append({
                    "type": entity_type,
                    "value": val,
                    "method": "nlp-remote",
                    "confidence": confidence,
                    "masked_value": token,
                })

        return masked_text, entities


# Thread-safe singleton

_scanner_lock = threading.Lock()
_scanner_instance: Optional[PresidioScanner] = None


def get_scanner() -> PresidioScanner:
    """Return the process-wide scanner singleton (lazy-init, thread-safe)."""
    global _scanner_instance
    if _scanner_instance is None:
        with _scanner_lock:
            if _scanner_instance is None:
                import os
                scanner_type = os.environ.get("MASK_SCANNER_TYPE", "local").lower()
                if scanner_type == "remote":
                    url = os.environ.get("MASK_SCANNER_URL", "http://localhost:5001/analyze")
                    _scanner_instance = RemotePresidioScanner(url)
                else:
                    _scanner_instance = PresidioScanner()
    return _scanner_instance
