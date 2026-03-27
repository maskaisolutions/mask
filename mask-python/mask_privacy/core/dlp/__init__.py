"""
DLP (Data Loss Prevention) sub-package for Mask Privacy SDK.

Provides multilingual entity detection, pattern-based classification,
hard-validation, and proximity-weighted confidence scoring that feeds
into the JIT / FPE encryption pipeline.
"""

from mask_privacy.core.dlp.assessor import LanguageContextResolver
from mask_privacy.core.dlp.registry import DLPPatternRegistry, SensitiveCategory
from mask_privacy.core.dlp.handlers import DLPValidationEngine
from mask_privacy.core.dlp.scorer import DLPConfidenceScorer

__all__ = [
    "LanguageContextResolver",
    "DLPPatternRegistry",
    "SensitiveCategory",
    "DLPValidationEngine",
    "DLPConfidenceScorer",
]
