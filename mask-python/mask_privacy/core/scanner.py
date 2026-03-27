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
import asyncio
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Optional, List, Dict, Callable, Awaitable, Any, Union

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

# DLP Pipeline imports — multilingual detection + 50-type registry
from mask_privacy.core.dlp.scorer import DLPConfidenceScorer
from mask_privacy.core.dlp.assessor import LanguageContextResolver
from mask_privacy.core.dlp.registry import DLPPatternRegistry
from mask_privacy.core.dlp.handlers import DLPValidationEngine
from mask_privacy import config

logger = logging.getLogger("mask.scanner")

from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeoutError

# Global variables for the worker processes (initialized per-worker)
_worker_analyzer = None

def _init_worker() -> None:
    """Initialize the Presidio Analyzer inside the worker process to avoid pickling models."""
    global _worker_analyzer
    import spacy
    import os
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    req_langs = [lang.strip().lower() for lang in config.MASK_LANGUAGES.split(",")]
    nlp_engine_name = config.MASK_NLP_ENGINE
    
    models_config = []
    supported_langs = []
    
    if nlp_engine_name == "transformers" or "ar" in req_langs:
        hf_model = config.MASK_NLP_MODEL or "Davlan/bert-base-multilingual-cased-ner-hrl"
        for lang in req_langs:
            spacy_model = "en_core_web_sm"
            lang_to_spacy = {
                "en": ["en_core_web_sm"], "es": ["es_core_news_sm"], "fr": ["fr_core_news_sm"],
                "de": ["de_core_news_sm"], "tr": ["tr_core_news_trf", "en_core_web_sm"], 
                "ar": ["en_core_web_sm"], "ja": ["ja_core_news_sm"], "zh": ["zh_core_web_sm"]
            }
            for c in lang_to_spacy.get(lang, ["en_core_web_sm"]):
                if spacy.util.is_package(c):
                    spacy_model = c
                    break
            
            models_config.append({
                "lang_code": lang,
                "model_name": {"spacy": spacy_model, "transformers": hf_model}
            })
            supported_langs.append(lang)
            
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "transformers",
            "models": models_config,
            "ner_model_configuration": {
                "model_to_presidio_entity_mapping": {
                    "PER": "PERSON", "PERSON": "PERSON", "LOC": "LOCATION", "LOCATION": "LOCATION",
                    "GPE": "LOCATION", "ORG": "ORGANIZATION", "ORGANIZATION": "ORGANIZATION"
                },
                "low_confidence_score_multiplier": 0.4,
                "low_score_entity_names": ["ORGANIZATION", "ORG"],
                "default_score": 0.85
            }
        })
    else:
        lang_to_spacy_map = {
            "en": ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"],
            "es": ["es_core_news_lg", "es_core_news_md", "es_core_news_sm"],
            "fr": ["fr_core_news_lg", "fr_core_news_md", "fr_core_news_sm"],
            "de": ["de_core_news_lg", "de_core_news_md", "de_core_news_sm"],
            "tr": ["tr_core_news_trf", "en_core_web_lg"],
            "ja": ["ja_core_news_lg", "ja_core_news_md", "ja_core_news_sm"],
            "zh": ["zh_core_web_lg", "zh_core_web_md", "zh_core_web_sm"],
            "ar": ["en_core_web_sm"]
        }
        for lang in req_langs:
            selected_model = None
            for m in lang_to_spacy_map.get(lang, ["en_core_web_sm"]):
                if spacy.util.is_package(m):
                    selected_model = m
                    break
            if selected_model:
                models_config.append({"lang_code": lang, "model_name": selected_model})
                supported_langs.append(lang)
            else:
                logger.warning(f"No spaCy model found for language '{lang}'.")
        
        if not models_config:
            return
            
        provider = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": models_config})
        
    _worker_analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=supported_langs)

def _run_analyzer(text: str, entities: List[str], language: str = "en") -> Any:
    """Top-level function to be executed by the ProcessPoolExecutor."""
    if _worker_analyzer is None:
        raise RuntimeError("Scanner worker not initialized with NLP model.")
    if language not in _worker_analyzer.supported_languages:
        language = _worker_analyzer.supported_languages[0] if _worker_analyzer.supported_languages else "en"
    return _worker_analyzer.analyze(text=text, entities=entities, language=language)

import threading

# Persistent process pool for NLP analysis to aggressively isolate heavy compute and avoid the GIL
_SCANNER_POOL = None
_POOL_LOCK = threading.Lock()

def _get_scanner_pool() -> ProcessPoolExecutor:
    global _SCANNER_POOL
    if _SCANNER_POOL is None:
        with _POOL_LOCK:
            if _SCANNER_POOL is None:
                _SCANNER_POOL = ProcessPoolExecutor(
                    max_workers=config.MASK_NLP_MAX_WORKERS,
                    initializer=_init_worker
                )
    return _SCANNER_POOL

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

# ── DLP pipeline singletons (lazy-init, lightweight) ─────────────────────────
_dlp_lang_resolver = LanguageContextResolver()
_dlp_pattern_registry = DLPPatternRegistry()
_dlp_validation_engine = DLPValidationEngine()
_dlp_confidence_scorer = DLPConfidenceScorer()


# Scanner class

class PresidioScanner:
    """Tiered Waterfall scanner for PII detection.

    Tier 1 (Deterministic) runs Regex + Luhn checksums.
    Tier 2 (Probabilistic) runs Presidio NLP on the *remaining* text.
    """

    def __init__(self) -> None:
        logger.info("Initializing PresidioScanner. Workers will load models based on MASK_LANGUAGES.")

        self._supported_entities = [
            "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD",
            "US_BANK_NUMBER", "CRYPTO", "IBAN_CODE", "IP_ADDRESS", "PERSON",
        ]

    def set_supported_entities(self, entities: List[str]) -> None:
        """Replace the entity detection list."""
        self._supported_entities = list(entities)
        logger.info("Scanner entities updated: %s", self._supported_entities)

    # Tier 0 — DLP Heuristic Pipeline (multilingual, 50+ types)
    def _tier0_dlp_heuristic(
        self,
        text: str,
        encode_fn,
        confidence_threshold: float,
    ) -> tuple[str, List[Dict]]:
        """Run the DLP pattern registry with language-aware scoring.

        This tier executes *before* the legacy regex / NLP tiers and removes
        validated matches from the text buffer to avoid double-detection.
        """
        detected_language = _dlp_lang_resolver.resolve(text)
        logger.debug("DLP language context: %s", detected_language)

        raw_hits: list[tuple[int, int, str, str, float]] = []

        # Pass 1: Structured patterns from the registry
        for type_tag, descriptor in _dlp_pattern_registry.iter_descriptors():
            for m in descriptor.compiled_re.finditer(text):
                matched_str = m.group(0)
                if looks_like_token(matched_str):
                    continue
                validator_result = _dlp_validation_engine.run(
                    descriptor.validator_tag, matched_str
                )
                conf = _dlp_confidence_scorer.score(
                    base_risk=descriptor.base_risk,
                    match_start=m.start(),
                    match_end=m.end(),
                    full_text=text,
                    proximity_terms=descriptor.proximity_terms,
                    validator_passed=validator_result,
                )
                if conf >= confidence_threshold:
                    raw_hits.append((m.start(), m.end(), type_tag, matched_str, conf))

        # Pass 2: Locale-tuned name patterns
        for name_re in _dlp_pattern_registry.name_patterns_for(detected_language):
            for m in name_re.finditer(text):
                if looks_like_token(m.group(0)):
                    continue
                conf = _dlp_confidence_scorer.score(
                    base_risk=0.50,
                    match_start=m.start(),
                    match_end=m.end(),
                    full_text=text,
                    proximity_terms=frozenset({"name", "contact", "person", "nom", "isim", "اسم"}),
                    validator_passed=None,
                )
                if conf >= confidence_threshold:
                    raw_hits.append((m.start(), m.end(), "PERSON_NAME", m.group(0), conf))

        # Pass 3: Locale-tuned address patterns
        for addr_re in _dlp_pattern_registry.address_patterns_for(detected_language):
            for m in addr_re.finditer(text):
                if looks_like_token(m.group(0)):
                    continue
                raw_hits.append((m.start(), m.end(), "PHYS_ADDRESS", m.group(0), 0.55))

        # De-duplicate overlapping spans — keep longer / higher-confidence match
        raw_hits.sort(key=lambda h: (h[0], -(h[1] - h[0]), -h[4]))
        deduped: list[tuple[int, int, str, str, float]] = []
        occupied_end = -1
        for start, end, tag, val, conf in raw_hits:
            if start >= occupied_end:
                deduped.append((start, end, tag, val, conf))
                occupied_end = end

        # Replace right-to-left to preserve offsets
        entities: List[Dict] = []
        excised = text
        for start, end, tag, val, conf in reversed(deduped):
            token = encode_fn(val)
            excised = excised[:start] + token + excised[end:]
            entities.append({
                "start": start,
                "end": end,
                "type": tag,
                "value": val,
                "method": "dlp_heuristic",
                "confidence": conf,
                "masked_value": token,
                "language": detected_language,
            })

        return excised, entities

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
                    "start": start,
                    "end": end,
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

        timeout = config.MASK_NLP_TIMEOUT_SECONDS

        entities: List[Dict] = []

        # Run the heavy NLP analysis in the Process Pool
        lang = _dlp_lang_resolver.resolve(text)
        pool = _get_scanner_pool()
        future = pool.submit(
            _run_analyzer,
            text, self._supported_entities, lang
        )
        try:
            results = future.result(timeout=timeout)
        except FuturesTimeoutError:
            # Try to cancel to free up pool resources
            future.cancel()
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

        pipeline = pipeline or ["dlp", "regex", "checksum", "nlp"]
        _encode = encode_fn or encode
        boost = self._resolve_boost(context)

        # --- Tier 0: DLP Heuristic (multilingual, 50+ types) ---
        if "dlp" in pipeline:
            text, _ = self._tier0_dlp_heuristic(text, _encode, confidence_threshold)

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

        pipeline = pipeline or ["dlp", "regex", "checksum", "nlp"]
        _encode = encode_fn or encode
        boost = self._resolve_boost(context)
        all_entities: List[Dict] = []

        remaining = text

        if "dlp" in pipeline:
            remaining, tier0 = self._tier0_dlp_heuristic(remaining, _encode, confidence_threshold)
            all_entities.extend(tier0)

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
        encode_fn: Optional[Callable[[str], Awaitable[str]]] = None,
        pipeline: Optional[List[str]] = None,
        confidence_threshold: float = 0.7,
        context: Optional[str] = None,
        aggressive: bool = False,
    ) -> str:
        """Native async version of ``scan_and_tokenize``.
        
        This method is non-blocking: it runs the Tier 2 NLP in a process pool
        and waits for the result without blocking the asyncio event loop.
        """
        if not text or not isinstance(text, str):
            return text

        pipeline = pipeline or ["dlp", "regex", "checksum", "nlp"]
        
        # Default to vault.aencode if not provided
        if encode_fn is None:
            from mask_privacy.core.vault import aencode
            _encode = aencode
        else:
            _encode = encode_fn
            
        boost = self._resolve_boost(context)

        # --- Tier 0: DLP Heuristic (sync, fast) ---
        if "dlp" in pipeline:
            # DLP tier uses sync encode via identity pass then async encode
            _, dlp_entities = self._tier0_dlp_heuristic(text, lambda x: x, confidence_threshold)
            if dlp_entities:
                vals = [e["value"] for e in dlp_entities]
                tokens = await asyncio.gather(*[_encode(v) for v in vals])
                dlp_entities.sort(key=lambda x: x.get("start", 0), reverse=True)
                for i, e in enumerate(reversed(dlp_entities)):
                    idx = len(dlp_entities) - 1 - i
                    text = text[:dlp_entities[idx]["start"]] + tokens[idx] + text[dlp_entities[idx]["end"]:]

        # --- Tier 1: Deterministic ---
        if "regex" in pipeline or "checksum" in pipeline:
            _, entities = self._tier1_regex(text, lambda x: x, boost, aggressive, confidence_threshold)
            if entities:
                vals = [e["value"] for e in entities]
                tokens = await asyncio.gather(*[_encode(v) for v in vals])
                entities.sort(key=lambda x: x.get("start", 0), reverse=True)
                for i, e in enumerate(reversed(entities)):
                    idx = len(entities) - 1 - i
                    text = text[:entities[idx]["start"]] + tokens[idx] + text[entities[idx]["end"]:]

        # --- Tier 2: Probabilistic (on the *remaining* text) ---
        if "nlp" in pipeline:
            text, _ = await self._atier2_nlp(text, _encode, boost, aggressive, confidence_threshold)

        return text

    async def ascan_and_return_entities(
        self,
        text: str,
        encode_fn: Optional[Callable[[str], Awaitable[str]]] = None,
        pipeline: Optional[List[str]] = None,
        confidence_threshold: float = 0.7,
        context: Optional[str] = None,
        aggressive: bool = False,
    ) -> List[Dict]:
        """Async version of ``scan_and_return_entities``."""
        if not text or not isinstance(text, str):
            return []

        pipeline = pipeline or ["dlp", "regex", "checksum", "nlp"]
        if encode_fn is None:
            from mask_privacy.core.vault import aencode
            _encode = aencode
        else:
            _encode = encode_fn
            
        boost = self._resolve_boost(context)
        all_entities: List[Dict] = []

        remaining = text

        if "dlp" in pipeline:
            _, tier0 = self._tier0_dlp_heuristic(remaining, lambda x: x, confidence_threshold)
            if tier0:
                vals = [e["value"] for e in tier0]
                tokens = await asyncio.gather(*[_encode(v) for v in vals])
                for i, t in enumerate(tokens):
                    tier0[i]["masked_value"] = t
                all_entities.extend(tier0)
                tier0_sorted = sorted(tier0, key=lambda x: x["start"], reverse=True)
                for e in tier0_sorted:
                    remaining = remaining[:e["start"]] + e["masked_value"] + remaining[e["end"]:]

        if "regex" in pipeline or "checksum" in pipeline:
            _, tier1 = self._tier1_regex(remaining, lambda x: x, boost, aggressive, confidence_threshold)
            if tier1:
                vals = [e["value"] for e in tier1]
                tokens = await asyncio.gather(*[_encode(v) for v in vals])
                for i, t in enumerate(tokens):
                    tier1[i]["masked_value"] = t
                all_entities.extend(tier1)
                tier1_sorted = sorted(tier1, key=lambda x: x["start"], reverse=True)
                for e in tier1_sorted:
                    remaining = remaining[:e["start"]] + e["masked_value"] + remaining[e["end"]:]

        if "nlp" in pipeline:
            _, tier2 = await self._atier2_nlp(remaining, _encode, boost, aggressive, confidence_threshold)
            all_entities.extend(tier2)

        return all_entities

    async def _atier2_nlp(
        self,
        text: str,
        encode_fn: Callable[[str], Awaitable[str]],
        boost_entities: frozenset,
        aggressive: bool,
        confidence_threshold: float,
    ) -> tuple[str, List[Dict]]:
        """Async version of _tier2_nlp that uses asyncio.wrap_future."""
        import asyncio
        from concurrent.futures import TimeoutError as FuturesTimeoutError
        from mask_privacy.core.exceptions import MaskNLPTimeout

        timeout = config.MASK_NLP_TIMEOUT_SECONDS
        entities: List[Dict] = []

        lang = _dlp_lang_resolver.resolve(text)
        pool = _get_scanner_pool()
        future = pool.submit(_run_analyzer, text, self._supported_entities, lang)
        
        # Convert to asyncio future
        loop = asyncio.get_event_loop()
        try:
            results = await asyncio.wait_for(asyncio.wrap_future(future), timeout=timeout)
        except (asyncio.TimeoutError, FuturesTimeoutError):
            future.cancel()
            raise MaskNLPTimeout(f"Presidio analysis exceeded {timeout}s timeout")

        masked_text = text
        results.sort(key=lambda r: r.start, reverse=True)
        
        # Collection phase: find all values to encode
        to_encode = []
        valid_results = []
        for r in results:
            confidence = r.score if hasattr(r, "score") else 0.7
            if aggressive or r.entity_type.lower().replace("_", " ") in boost_entities:
                confidence = min(1.0, confidence + 0.2)
            
            val = text[r.start:r.end]
            if confidence >= confidence_threshold and not looks_like_token(val):
                to_encode.append(val)
                valid_results.append((r, confidence))

        # Parallel encode
        tokens = await asyncio.gather(*[encode_fn(v) for v in to_encode])

        # Replacement phase (right to left)
        for i, (r, confidence) in enumerate(valid_results):
            token = tokens[i]
            val = text[r.start:r.end]
            masked_text = masked_text[:r.start] + token + masked_text[r.end:]
            entities.append({
                "type": r.entity_type,
                "value": val,
                "method": "nlp",
                "confidence": confidence,
                "masked_value": token,
                "start": r.start, # Add start/end for async processing
                "end": r.end,
            })

        return masked_text, entities


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

    async def _atier2_nlp(
        self,
        text: str,
        encode_fn: Callable[[str], Awaitable[str]],
        boost_entities: frozenset,
        aggressive: bool,
        confidence_threshold: float,
    ) -> tuple[str, List[Dict]]:
        """Async version of remote NLP scan using httpx.AsyncClient."""
        import httpx
        entities: List[Dict] = []
        
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    self.endpoint_url,
                    json={"text": text, "language": "en"},
                    timeout=30.0
                )
                resp.raise_for_status()
                results = resp.json()
        except Exception as e:
            logger.error("Remote NLP scan failed: %s", e)
            return text, []

        masked_text = text
        results.sort(key=lambda r: r.get("start", 0), reverse=True)
        
        # Collection & Parallel Encode
        to_encode = []
        valid_results = []
        for r in results:
            start, end, entity_type = r["start"], r["end"], r["entity_type"]
            confidence = r.get("score", 0.7)
            if aggressive or entity_type.lower().replace("_", " ") in boost_entities:
                confidence = min(1.0, confidence + 0.2)

            val = text[start:end]
            if confidence >= confidence_threshold and not looks_like_token(val):
                to_encode.append(val)
                valid_results.append((r, confidence))

        tokens = await asyncio.gather(*[encode_fn(v) for v in to_encode])

        for i, (r, confidence) in enumerate(valid_results):
            token = tokens[i]
            start, end = r["start"], r["end"]
            val = text[start:end]
            masked_text = masked_text[:start] + token + masked_text[end:]
            entities.append({
                "type": r["entity_type"],
                "value": val,
                "method": "nlp-remote",
                "confidence": confidence,
                "masked_value": token,
            })

        return masked_text, entities

    async def ascan_and_tokenize(
        self,
        text: str,
        encode_fn: Optional[Callable[[str], Awaitable[str]]] = None,
        pipeline: Optional[List[str]] = None,
        confidence_threshold: float = 0.7,
        context: Optional[str] = None,
        aggressive: bool = False,
    ) -> str:
        """Native async version for RemotePresidioScanner."""
        if not text or not isinstance(text, str):
            return text

        if encode_fn is None:
            from mask_privacy.core.vault import aencode
            _encode = aencode
        else:
            _encode = encode_fn
            
        boost = self._resolve_boost(context)
        
        # Remote scanner only supports 'nlp' currently, but we follow the pipeline
        pipeline = pipeline or ["nlp"]
        if "nlp" in pipeline:
            text, _ = await self._atier2_nlp(text, _encode, boost, aggressive, confidence_threshold)
            
        return text


# Thread-safe singleton

_scanner_lock = threading.Lock()
_scanner_instance: Optional[PresidioScanner] = None


def get_scanner() -> PresidioScanner:
    """Return the process-wide scanner singleton (lazy-init, thread-safe)."""
    global _scanner_instance
    if _scanner_instance is None:
        with _scanner_lock:
            if _scanner_instance is None:
                scanner_type = config.MASK_SCANNER_TYPE
                if scanner_type == "remote":
                    url = config.MASK_SCANNER_URL
                    _scanner_instance = RemotePresidioScanner(url)
                else:
                    _scanner_instance = PresidioScanner()
    return _scanner_instance


def close_scanner() -> None:
    """Shutdown the scanner process pool. Usually called via atexit."""
    with _POOL_LOCK:
        if _SCANNER_POOL:
            _SCANNER_POOL.shutdown(wait=True)
            logger.info("Scanner process pool shut down.")


# Register graceful shutdown
import atexit
atexit.register(close_scanner)
