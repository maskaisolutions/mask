"""
Entity Detection Scanner utilizing Microsoft Presidio.

Scans unstructured text to identify PII (Emails, Phones, SSNs, Credit Cards)
and replaces them in-place with Format-Preserving Encryption (FPE) tokens
so that the LLM only sees tokenized shapes but never the raw text.
"""

import logging
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

from mask.core.vault import encode
from mask.core.fpe import generate_fpe_token

logger = logging.getLogger("mask.scanner")


class PresidioScanner:
    """Wrapper around Microsoft Presidio to tokenize substrings."""

    _instance: Optional["PresidioScanner"] = None

    def __new__(cls) -> "PresidioScanner":
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._init()
            cls._instance = instance
        return cls._instance

    def _init(self) -> None:
        import spacy
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        logger.info("Initializing Microsoft Presidio Analyzer...")
        
        # Detect available spaCy models
        available_models = []
        for model in ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"]:
            if spacy.util.is_package(model):
                available_models.append(model)
        
        if not available_models:
            raise ImportError(
                "Mask: Missing AI Model. To enable PII protection, please run: "
                "pip install \"maskcloud[sm]\" (Small) or pip install \"maskcloud[lg]\" (Large)."
            )
            
        selected_model = available_models[0]
        logger.info(f"Using spaCy model: {selected_model}")
        
        # Configure NLP engine
        configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": selected_model}]
        }
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        
        self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        self._anonymizer = AnonymizerEngine()
        
        # We target specific entities that map cleanly to our SDK's existing FPE formats
        self._supported_entities = [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "US_SSN",
            "CREDIT_CARD",
            "US_BANK_NUMBER",
            "CRYPTO",
            "IBAN_CODE",
            "IP_ADDRESS",
            "PERSON", # generic opaque token fallback
        ]

    def scan_and_tokenize(self, text: str, encode_fn: Optional[Callable[[str], str]] = None) -> str:
        """Scan a string and replace PII with FPE tokens.
        
        Uses Presidio Analyzer to find entity bounding boxes, then uses
        Presidio Anonymizer with a custom lambda operator to trigger the
        provided `encode_fn` (or the global Mask `encode` function)
        on those specific substrings.
        """
        if not text or not isinstance(text, str):
            return text

        # 1. Analyze
        results = self._analyzer.analyze(
            text=text, 
            entities=self._supported_entities, 
            language="en"
        )
        
        if not results:
            return text

        # 2. Custom Anonymizer Operator 
        # Whenever presidio finds an entity, pass the text chunk to the encode mechanism
        def _fpe_tokenize(pii_text: str) -> str:
            if encode_fn:
                return encode_fn(pii_text)
            return encode(pii_text)

        operators = {
            entity_type: OperatorConfig("custom", {"lambda": _fpe_tokenize})
            for entity_type in self._supported_entities
        }

        # 3. Anonymize (replace inline)
        anonymized_result = self._anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )
        
        return anonymized_result.text

def get_scanner() -> PresidioScanner:
    """Singleton getter for the scanner."""
    return PresidioScanner()
