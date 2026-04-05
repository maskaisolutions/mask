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

import re
import logging
import asyncio
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Optional, List, Dict, Callable, Awaitable, Any

from mask_privacy.core.vault import encode
from mask_privacy.core.fpe import looks_like_token
from mask_privacy.core.span import Span, resolve_overlaps, reconstruct

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
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    req_langs = [lang.strip().lower() for lang in config.MASK_LANGUAGES.split(",")]
    # Restrict to supported languages only
    req_langs = [l for l in req_langs if l in ("en", "es")]
    if not req_langs:
        req_langs = ["en"]

    lang_to_spacy_map = {
        "en": ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"],
        "es": ["es_core_news_lg", "es_core_news_md", "es_core_news_sm"],
    }
    models_config = []
    supported_langs = []
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
        self.registry = DLPPatternRegistry()
        self.lang_resolver = LanguageContextResolver()
        self.validation_engine = DLPValidationEngine()

        self._supported_entities = [
            "PERSON", "LOCATION", "ORGANIZATION",
        ]

    def set_supported_entities(self, entities: List[str]) -> None:
        """Replace the entity detection list."""
        self._supported_entities = list(entities)
        logger.info("Scanner entities updated: %s", self._supported_entities)

    # Tier 0 — DLP Heuristic Pipeline (multilingual, 50+ types)
    def _tier0_collect_spans(
        self,
        text: str,
        confidence_threshold: float,
        locale: Optional[str] = None,
    ) -> List[Span]:
        """Run the DLP pattern registry using Category Mega-Regexes.

        Returns a flat list of ``Span`` objects.  No string mutation occurs
        here — all encoding and text reconstruction happens in one final pass
        after all tiers have collected their spans.

        Each category now returns a ``List[re.Pattern]`` (at most two: one
        case-sensitive, one case-insensitive) so that flag bleed between
        sub-groups is impossible.

        ``locale`` may be pre-resolved by a caller (async path) to avoid
        running language detection twice on a mutated text buffer.
        """
        if locale is None:
            locale = self.lang_resolver.resolve(text)
        logger.debug("DLP language context: %s", locale)

        spans: List[Span] = []
        # Returns Dict[cat_key, List[re.Pattern]] — at most 2 per category
        category_regexes = self.registry.get_category_regexes(locale=locale)

        # Pass 1: Category Mega-Regexes (O(text) per category/sub-group)
        for cat_key, regex_list in category_regexes.items():
            for mega_re in regex_list:
                for m in mega_re.finditer(text):
                    type_tag = m.lastgroup
                    if type_tag is None:
                        continue
                    matched_str = m.group(0)
                    if looks_like_token(matched_str):
                        continue
                    descriptor = self.registry.descriptor_for(type_tag)
                    if descriptor is None:
                        continue

                    validator_result = self.validation_engine.run(
                        descriptor.validator_tag, matched_str
                    )

                    # FUZZY FAIL-SAFE logic
                    if validator_result is False:
                        if descriptor.is_high_entropy:
                            conf = 0.85  # Higher than generic Phone (0.80)
                        else:
                            continue
                    else:
                        conf = _dlp_confidence_scorer.score(
                            base_risk=descriptor.base_risk,
                            match_start=m.start(),
                            match_end=m.end(),
                            full_text=text,
                            proximity_terms=descriptor.proximity_terms,
                            validator_passed=validator_result,
                        )

                    if conf >= confidence_threshold:
                        spans.append(Span(
                            start=m.start(),
                            end=m.end(),
                            entity_type=type_tag,
                            original_value=matched_str,
                            confidence=conf,
                            method="dlp_heuristic",
                            language=locale,
                            rule_id=descriptor.rule_id,
                            compliance_scope=descriptor.compliance_scope,
                        ))

        # Pass 2: Locale-tuned name patterns (JIT — only for detected language)
        name_proximity = frozenset({"name", "contact", "person", "nom", "isim", "\u0627\u0633\u0645"})
        for name_re in self.registry.name_patterns_for(locale):
            for m in name_re.finditer(text):
                if looks_like_token(m.group(0)):
                    continue
                conf = _dlp_confidence_scorer.score(
                    base_risk=0.50,
                    match_start=m.start(),
                    match_end=m.end(),
                    full_text=text,
                    proximity_terms=name_proximity,
                    validator_passed=None,
                )
                if conf >= confidence_threshold:
                    spans.append(Span(
                        start=m.start(),
                        end=m.end(),
                        entity_type="PERSON_NAME",
                        original_value=m.group(0),
                        confidence=conf,
                        method="dlp_heuristic",
                        language=locale,
                    ))

        # Pass 3: Locale-tuned address patterns (JIT)
        for addr_re in self.registry.address_patterns_for(locale):
            for m in addr_re.finditer(text):
                if looks_like_token(m.group(0)):
                    continue
                spans.append(Span(
                    start=m.start(),
                    end=m.end(),
                    entity_type="PHYS_ADDRESS",
                    original_value=m.group(0),
                    confidence=0.55,
                    method="dlp_heuristic",
                    language=locale,
                ))

        return spans

    # ── Legacy shim: preserves backward-compat for external callers ───────────
    def _tier0_dlp_heuristic(
        self,
        text: str,
        encode_fn,
        confidence_threshold: float,
    ) -> tuple[str, List[Dict]]:
        """Backward-compat wrapper — collects spans then does a single-pass encode."""
        spans = self._tier0_collect_spans(text, confidence_threshold)
        resolved = resolve_overlaps(spans)
        entities: List[Dict] = []
        for span in resolved:
            try:
                span.masked_value = encode_fn(span.original_value, entity_type=span.entity_type)
            except TypeError:
                span.masked_value = encode_fn(span.original_value)
            entities.append({
                "start": span.start, "end": span.end, "type": span.entity_type,
                "value": span.original_value, "method": span.method,
                "confidence": span.confidence, "masked_value": span.masked_value,
                "language": span.language,
                "rule_id": span.rule_id,
                "compliance_scope": list(span.compliance_scope) if span.compliance_scope else [],
            })
        return reconstruct(text, resolved), entities

    # Tier 1 — Deterministic detection (Legacy: Redirected to DLP)
    def _tier1_collect_spans(
        self,
        text: str,
        boost_entities: frozenset,
        aggressive: bool,
        confidence_threshold: float,
    ) -> List[Span]:
        """Redirected to DLP Tier 0."""
        return self._tier0_collect_spans(text, confidence_threshold)

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
                try:
                    token = encode_fn(val, entity_type=r.entity_type)
                except TypeError:
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
        """Determine which entity types should get a confidence boost.

        Proximity terms are matched on whole-word boundaries only (``\\b``)
        to prevent short terms such as ``"id"`` from matching inside unrelated
        words like ``"hidden"`` or ``"provider"``.
        """
        if not context:
            return frozenset()
        boosted = set()
        for _, desc in self.registry.iter_descriptors():
            for term in desc.proximity_terms:
                pattern = r"\b" + re.escape(term) + r"\b"
                if re.search(pattern, context, re.IGNORECASE):
                    boosted.add(desc.category.value.lower())
                    break  # one term match is enough for this descriptor
        return frozenset(boosted)

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

        # ── Span-accumulation phase (no string mutation) ──────────────────
        all_spans: List[Span] = []

        if "dlp" in pipeline:
            all_spans.extend(self._tier0_collect_spans(text, confidence_threshold))

        if "regex" in pipeline or "checksum" in pipeline:
            all_spans.extend(self._tier1_collect_spans(text, boost, aggressive, confidence_threshold))

        # ── Resolve overlaps across ALL deterministic tiers in one pass ───
        resolved = resolve_overlaps(all_spans)
        for span in resolved:
            try:
                span.masked_value = _encode(span.original_value, entity_type=span.entity_type)
            except TypeError:
                span.masked_value = _encode(span.original_value)

        # Apply deterministic masks in a single string reconstruction
        text = reconstruct(text, resolved)

        # ── Tier 2: Probabilistic NLP (runs on already-masked text) ──────
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

        # ── Span-accumulation phase ───────────────────────────────────────
        all_spans: List[Span] = []

        if "dlp" in pipeline:
            all_spans.extend(self._tier0_collect_spans(text, confidence_threshold))

        if "regex" in pipeline or "checksum" in pipeline:
            all_spans.extend(self._tier1_collect_spans(text, boost, aggressive, confidence_threshold))

        resolved = resolve_overlaps(all_spans)
        for span in resolved:
            try:
                span.masked_value = _encode(span.original_value, entity_type=span.entity_type)
            except TypeError:
                span.masked_value = _encode(span.original_value)
            all_entities.append({
                "start": span.start, "end": span.end, "type": span.entity_type,
                "value": span.original_value, "method": span.method,
                "confidence": span.confidence, "masked_value": span.masked_value,
                "language": span.language,
                "rule_id": span.rule_id,
                "compliance_scope": list(span.compliance_scope) if span.compliance_scope else [],
            })

        remaining = reconstruct(text, resolved)

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

        Non-blocking: heavy CPU span-collection is offloaded to a thread via
        ``asyncio.to_thread`` so the event loop is never blocked by mega-regex
        work.  The language locale is resolved *once* from the original text
        and passed down to every tier to prevent NLP mis-classification after
        tokens replace PII substrings.
        """
        if not text or not isinstance(text, str):
            return text

        pipeline = pipeline or ["dlp", "regex", "checksum", "nlp"]

        if encode_fn is None:
            from mask_privacy.core.vault import aencode
            _encode = aencode
        else:
            _encode = encode_fn

        boost = self._resolve_boost(context)

        # ── Freeze locale from ORIGINAL text before any mutation ───────────
        locale = self.lang_resolver.resolve(text)

        # ── Span-accumulation phase (offloaded to thread pool) ────────────
        all_spans: List[Span] = []

        if "dlp" in pipeline:
            spans = await asyncio.to_thread(
                self._tier0_collect_spans, text, confidence_threshold, locale
            )
            all_spans.extend(spans)

        if "regex" in pipeline or "checksum" in pipeline:
            spans = await asyncio.to_thread(
                self._tier1_collect_spans, text, boost, aggressive, confidence_threshold
            )
            all_spans.extend(spans)

        # ── Resolve overlaps; encode all deterministic tokens in parallel ──
        resolved = resolve_overlaps(all_spans)
        if resolved:
            _semaphore = asyncio.Semaphore(50)

            async def _enc(v: str, t: str) -> str:
                async with _semaphore:
                    try:
                        return await _encode(v, entity_type=t)
                    except TypeError:
                        return await _encode(v)

            tokens = await asyncio.gather(
                *[_enc(span.original_value, span.entity_type) for span in resolved]
            )
            # Assign masked values BEFORE any reordering
            for span, token in zip(resolved, tokens):
                span.masked_value = token

        # Single-pass string reconstruction (right-to-left, no offset drift)
        text = reconstruct(text, resolved)

        # ── Tier 2: Probabilistic NLP (on already-masked text) ───────────
        if "nlp" in pipeline:
            text, _ = await self._atier2_nlp(
                text, _encode, boost, aggressive, confidence_threshold, locale=locale
            )

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
        """Async version of ``scan_and_return_entities``.

        Refactored to use the Span-First accumulation pattern for safety.
        Uses asyncio.Semaphore to cap encoding concurrency at 50.
        """
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

        # ── Freeze locale from ORIGINAL text before any mutation ───────────
        locale = self.lang_resolver.resolve(text)

        # ── Span-accumulation phase (mirrors ascan_and_tokenize) ───────────
        all_spans: List[Span] = []

        if "dlp" in pipeline:
            spans = await asyncio.to_thread(
                self._tier0_collect_spans, text, confidence_threshold, locale
            )
            all_spans.extend(spans)

        if "regex" in pipeline or "checksum" in pipeline:
            spans = await asyncio.to_thread(
                self._tier1_collect_spans, text, boost, aggressive, confidence_threshold
            )
            all_spans.extend(spans)

        # ── Resolve overlaps; encode with bounded concurrency ─────────────
        resolved = resolve_overlaps(all_spans)
        if resolved:
            _semaphore = asyncio.Semaphore(50)

            async def _enc(v: str, t: str) -> str:
                async with _semaphore:
                    try:
                        return await _encode(v, entity_type=t)
                    except TypeError:
                        return await _encode(v)

            tokens = await asyncio.gather(
                *[_enc(span.original_value, span.entity_type) for span in resolved]
            )
            for span, token in zip(resolved, tokens):
                span.masked_value = token

        for span in resolved:
            all_entities.append({
                "start": span.start, "end": span.end, "type": span.entity_type,
                "value": span.original_value, "method": span.method,
                "confidence": span.confidence, "masked_value": span.masked_value,
                "language": span.language,
                "rule_id": span.rule_id,
                "compliance_scope": list(span.compliance_scope) if span.compliance_scope else [],
            })

        remaining = reconstruct(text, resolved)

        if "nlp" in pipeline:
            _, tier2 = await self._atier2_nlp(
                remaining, _encode, boost, aggressive, confidence_threshold, locale=locale
            )
            all_entities.extend(tier2)

        return all_entities

    async def _atier2_nlp(
        self,
        text: str,
        encode_fn: Callable[[str], Awaitable[str]],
        boost_entities: frozenset,
        aggressive: bool,
        confidence_threshold: float,
        *,
        locale: Optional[str] = None,
    ) -> tuple[str, List[Dict]]:
        """Async version of _tier2_nlp that uses asyncio.wrap_future.

        ``locale`` should be the language tag resolved from the *original*
        unmasked text.  If omitted it is inferred from ``text`` (which may
        already be partially masked and therefore mis-classified).
        """
        import asyncio
        from concurrent.futures import TimeoutError as FuturesTimeoutError
        from mask_privacy.core.exceptions import MaskNLPTimeout

        timeout = config.MASK_NLP_TIMEOUT_SECONDS
        entities: List[Dict] = []

        # Use the pre-resolved locale; fall back to detecting from text only if
        # no frozen locale was passed (e.g. direct callers of this method).
        lang = locale if locale is not None else _dlp_lang_resolver.resolve(text)
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
        async def _enc(v, t):
            try: return await encode_fn(v, entity_type=t)
            except TypeError: return await encode_fn(v)
        tokens = await asyncio.gather(*[_enc(v, r.entity_type) for v, (r, _) in zip(to_encode, valid_results)])

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
