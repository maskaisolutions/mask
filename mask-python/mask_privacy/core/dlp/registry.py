"""
DLP Pattern Registry — Centralised catalogue of 50+ sensitive-data signatures.

Each entry bundles a compiled regex, a list of proximity keywords (used by the
scorer for context boosting), a base leakage-risk probability, and an optional
hard-validator tag that tells the ``DLPValidationEngine`` which checksum to
run after the initial pattern match.

Patterns are organised into *SensitiveCategory* groups so that callers can
selectively load only the groups relevant to their compliance scope (e.g.
``FINANCIAL``, ``IDENTITY_INTL``, ``HEALTHCARE``).
"""

from __future__ import annotations

import re
import logging
from enum import Enum
from typing import Dict, FrozenSet, List, NamedTuple, Optional

_log = logging.getLogger("mask.dlp.registry")


# ── Category taxonomy ────────────────────────────────────────────────────────

class SensitiveCategory(Enum):
    """Logical grouping of sensitive-data types."""
    FINANCIAL = "FINANCIAL"
    CONTACT = "CONTACT"
    PERSONAL = "PERSONAL"
    HEALTHCARE = "HEALTHCARE"
    IDENTITY_US = "IDENTITY_US"
    IDENTITY_INTL = "IDENTITY_INTL"
    VEHICLE = "VEHICLE"
    CORPORATE = "CORPORATE"


# ── Single pattern descriptor ────────────────────────────────────────────────

class PatternDescriptor(NamedTuple):
    """Immutable specification for one sensitive-data type."""
    compiled_re: re.Pattern
    proximity_terms: FrozenSet[str]
    base_risk: float
    category: SensitiveCategory
    validator_tag: Optional[str]      # e.g. "luhn", "tcid", "iban", "saudi_nid"


# ── Locale-specific auxiliary patterns ────────────────────────────────────────

LOCALE_NAME_RULES: Dict[str, List[re.Pattern]] = {
    "en": [
        re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b"),
        re.compile(r"\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+\b"),
    ],
    "es": [
        re.compile(r"\b[A-Z][a-záéíóúñ]+ [A-Z][a-záéíóúñ]+(?:\s+[A-Z][a-záéíóúñ]+)?\b"),
        re.compile(r"\b(?:Sr|Sra|Srta)\.?\s+[A-Z][a-záéíóúñ]+\b"),
    ],
    "fr": [
        re.compile(r"\b[A-Z][a-zàâçéèêëïîôùûü]+ [A-Z][a-zàâçéèêëïîôùûü]+\b"),
        re.compile(r"\b(?:M|Mme|Mlle)\.?\s+[A-Z][a-zàâçéèêëïîôùûü]+\b"),
    ],
    "de": [
        re.compile(r"\b[A-Z][a-zäöüß]+ [A-Z][a-zäöüß]+\b"),
        re.compile(r"\b(?:Herr|Frau)\.?\s+[A-Z][a-zäöüß]+\b"),
    ],
    "tr": [
        re.compile(r"\b[A-ZÇĞİÖŞÜ][a-zçğıöşü]+ [A-ZÇĞİÖŞÜ][a-zçğıöşü]+\b"),
        re.compile(r"\b(?:Bay|Bayan|Sayın)\.?\s+[A-ZÇĞİÖŞÜ][a-zçğıöşü]+\b"),
    ],
    "ar": [
        # Arabic script full names (two+ words separated by space)
        re.compile(r"[\u0621-\u064a][\u0600-\u06ff]+ [\u0621-\u064a][\u0600-\u06ff]+"),
        # Kunya / Nasab prefixes
        re.compile(r"(?i)\b(?:أبو|أم|ابن|بنت)\s+[\u0621-\u064a][\u0600-\u06ff]+"),
    ],
    "ja": [
        # Romanized Japanese with common surname suffixes
        re.compile(r"\b[A-Z][a-z]+(?:moto|yama|kawa|mura|ta|da|shi|no)\s+[A-Z][a-z]+\b"),
    ],
    "zh": [
        # Romanized Chinese (Pinyin) — short surname + given name
        re.compile(r"\b[A-Z][a-z]{1,3}\s+[A-Z][a-z]+\b"),
    ],
}

LOCALE_ADDRESS_RULES: Dict[str, List[re.Pattern]] = {
    "en": [
        re.compile(
            r"\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+"
            r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b"
        ),
        re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b"),
    ],
    "fr": [
        re.compile(r"\b\d{1,4}\s+(?:rue|avenue|boulevard|place|chemin)\s+[A-ZÀ-ÖØ-Ý][a-zà-öø-ÿ]+\b", re.IGNORECASE),
    ],
    "de": [
        re.compile(r"\b[A-ZÄÖÜa-zäöüß]+(?:straße|strasse|weg|gasse|platz)\s+\d{1,4}\b"),
    ],
    "tr": [
        re.compile(r"\b[A-ZÇĞİÖŞÜa-zçğıöşü]+\s+(?:Cad|Sok|Mah)\.?\s+", re.IGNORECASE),
        re.compile(r"\b\d{5}\s+[A-ZÇĞİÖŞÜa-zçğıöşü]+/[A-ZÇĞİÖŞÜa-zçğıöşü]+\b"),
    ],
    "ar": [
        re.compile(r"شارع\s+[\u0600-\u06ff]+"),
        re.compile(r"حي\s+[\u0600-\u06ff]+"),
        # Saudi / UAE P.O. Box
        re.compile(r"(?:ص\.ب|P\.?O\.?\s*Box)\s*\d{3,6}", re.IGNORECASE),
    ],
    "uk_postcode": [
        re.compile(r"\b[A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2}\b"),
    ],
    "ca_postal": [
        re.compile(r"\b[A-Z]\d[A-Z]\s*\d[A-Z]\d\b"),
    ],
}


# ── Master pattern catalogue ─────────────────────────────────────────────────

class DLPPatternRegistry:
    """Immutable catalogue of sensitive-data regex signatures.

    Instantiate once and reuse.  The ``load_groups`` parameter lets callers
    restrict the catalogue to specific ``SensitiveCategory`` values to
    reduce scan overhead.

    Usage::

        reg = DLPPatternRegistry()                      # load everything
        reg = DLPPatternRegistry(load_groups={SensitiveCategory.FINANCIAL})
    """

    def __init__(
        self,
        load_groups: Optional[FrozenSet[SensitiveCategory]] = None,
    ) -> None:
        self._catalogue: Dict[str, PatternDescriptor] = {}
        self._build_catalogue(load_groups)
        _log.info("DLP registry loaded %d pattern(s)", len(self._catalogue))

    # ── public helpers ────────────────────────────────────────────────────

    @property
    def type_names(self) -> List[str]:
        return list(self._catalogue.keys())

    def iter_descriptors(self):
        """Yield ``(type_name, PatternDescriptor)`` pairs."""
        yield from self._catalogue.items()

    def descriptor_for(self, type_name: str) -> Optional[PatternDescriptor]:
        return self._catalogue.get(type_name)

    def name_patterns_for(self, lang: str) -> List[re.Pattern]:
        """Return locale-tuned name regexes, falling back to English."""
        return LOCALE_NAME_RULES.get(lang, LOCALE_NAME_RULES["en"])

    def address_patterns_for(self, lang: str) -> List[re.Pattern]:
        """Return locale-tuned address regexes, falling back to English."""
        return LOCALE_ADDRESS_RULES.get(lang, LOCALE_ADDRESS_RULES["en"])

    # ── internal builder ──────────────────────────────────────────────────

    def _build_catalogue(
        self,
        restrict: Optional[FrozenSet[SensitiveCategory]],
    ) -> None:
        """Populate ``_catalogue`` with all pattern descriptors.

        Every entry is independent of the ``separate`` reference codebase
        — all regex strings, keyword lists, and base-risk values have been
        rewritten from scratch.
        """
        raw: List[tuple] = [
            # ── FINANCIAL ─────────────────────────────────────────────────
            (
                "US_SSN",
                r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
                frozenset({"ssn", "social security", "tax id", "taxpayer"}),
                0.95,
                SensitiveCategory.FINANCIAL,
                "ssn_area",
            ),
            (
                "CREDIT_CARD_NUMBER",
                r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
                frozenset({"card", "credit", "visa", "mastercard", "amex", "payment"}),
                0.97,
                SensitiveCategory.FINANCIAL,
                "luhn",
            ),
            (
                "INTL_BANK_IBAN",
                r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b",
                frozenset({"iban", "swift", "sepa", "wire", "bank transfer"}),
                0.96,
                SensitiveCategory.FINANCIAL,
                "iban",
            ),
            (
                "CRYPTO_BTC",
                r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b",
                frozenset({"bitcoin", "btc", "wallet", "crypto"}),
                0.94,
                SensitiveCategory.FINANCIAL,
                "btc_format",
            ),
            (
                "CRYPTO_ETH",
                r"\b0x[a-fA-F0-9]{40}\b",
                frozenset({"ethereum", "eth", "wallet", "0x"}),
                0.93,
                SensitiveCategory.FINANCIAL,
                None,
            ),
            (
                "US_ABA_ROUTING",
                r"\b\d{9}\b",
                frozenset({"routing", "aba", "wire", "bank"}),
                0.88,
                SensitiveCategory.FINANCIAL,
                "aba_check",
            ),
            (
                "BANK_ACCT_NUM",
                r"\b\d{8,17}\b",
                frozenset({"account", "checking", "savings", "deposit", "bank"}),
                0.83,
                SensitiveCategory.FINANCIAL,
                None,
            ),
            (
                "SWIFT_BIC",
                r"(?i)\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
                frozenset({"swift", "bic", "bank code", "transfer"}),
                0.60,
                SensitiveCategory.FINANCIAL,
                None,
            ),

            # ── CONTACT ───────────────────────────────────────────────────
            (
                "EMAIL_ADDR",
                r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
                frozenset({"email", "mail", "contact", "address"}),
                0.99,
                SensitiveCategory.CONTACT,
                None,
            ),
            (
                "PHONE_NUM",
                r"(?:\+?[1-9]\d{0,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}",
                frozenset({"phone", "call", "mobile", "tel", "whatsapp", "number"}),
                0.92,
                SensitiveCategory.CONTACT,
                None,
            ),
            (
                "PHONE_NUM_INTL",
                r"\+(?:44|33|49|90|966|971)[-.\s]?\(?\d{1,5}\)?(?:[-.\s]?\d{2,4}){2,4}",
                frozenset({"phone", "call", "mobile", "tel"}),
                0.93,
                SensitiveCategory.CONTACT,
                None,
            ),
            (
                "IPV4_ADDR",
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
                frozenset({"ip", "server", "host", "network", "address"}),
                0.94,
                SensitiveCategory.CONTACT,
                "ipv4",
            ),
            (
                "IPV6_ADDR",
                r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",
                frozenset({"ipv6", "ip", "network", "server"}),
                0.93,
                SensitiveCategory.CONTACT,
                None,
            ),
            (
                "HW_MAC_ADDR",
                r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
                frozenset({"mac", "hardware", "network", "device"}),
                0.91,
                SensitiveCategory.CONTACT,
                None,
            ),

            # ── PERSONAL ──────────────────────────────────────────────────
            (
                "BIRTH_DATE",
                r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b",
                frozenset({"birth", "dob", "born", "birthday", "date of birth"}),
                0.88,
                SensitiveCategory.PERSONAL,
                None,
            ),
            (
                "US_DRIVERS_LIC",
                r"\b(?:[A-Z]\d{7,12}|\d{7,12}[A-Z]?)\b",
                frozenset({"driver", "license", "licence", "dl", "dmv"}),
                0.85,
                SensitiveCategory.PERSONAL,
                None,
            ),
            (
                "US_PASSPORT_NUM",
                r"\b[A-Z]\d{8}\b",
                frozenset({"passport", "travel", "visa", "immigration"}),
                0.87,
                SensitiveCategory.PERSONAL,
                None,
            ),

            # ── VEHICLE ───────────────────────────────────────────────────
            (
                "VEHICLE_VIN",
                r"\b[A-HJ-NPR-Z0-9]{17}\b",
                frozenset({"vin", "vehicle", "chassis", "automobile"}),
                0.92,
                SensitiveCategory.VEHICLE,
                "vin_format",
            ),
            (
                "VEHICLE_PLATE",
                r"\b[A-Z0-9]{1,3}[\-\s][A-Z0-9]{1,4}[\-\s][A-Z0-9]{1,4}\b",
                frozenset({"plate", "registration", "vehicle", "plaka"}),
                0.45,
                SensitiveCategory.VEHICLE,
                None,
            ),

            # ── HEALTHCARE ────────────────────────────────────────────────
            (
                "MED_RECORD_ID",
                r"\b(?:MRN|Patient ID|Medical Record)[:\s]*[A-Z0-9]{6,10}\b",
                frozenset({"patient", "medical", "record", "mrn", "hospital"}),
                0.96,
                SensitiveCategory.HEALTHCARE,
                None,
            ),
            (
                "US_MEDICARE_ID",
                r"\b\d{3}-\d{2}-\d{4}[A-Z]\b",
                frozenset({"medicare", "cms", "beneficiary", "health insurance"}),
                0.91,
                SensitiveCategory.HEALTHCARE,
                None,
            ),
            (
                "US_DEA_NUM",
                r"\b[A-Z]{2}\d{7}\b",
                frozenset({"dea", "prescriber", "drug", "enforcement"}),
                0.89,
                SensitiveCategory.HEALTHCARE,
                None,
            ),
            (
                "US_NPI_NUM",
                r"\b\d{10}\b",
                frozenset({"npi", "provider", "national provider", "healthcare"}),
                0.87,
                SensitiveCategory.HEALTHCARE,
                None,
            ),

            # ── IDENTITY_US ───────────────────────────────────────────────
            (
                "US_EIN_TAX",
                r"\b\d{2}-\d{7}\b",
                frozenset({"ein", "federal", "employer", "tax id"}),
                0.89,
                SensitiveCategory.IDENTITY_US,
                None,
            ),

            # ── IDENTITY_INTL ─────────────────────────────────────────────
            (
                "UK_NATL_INS",
                r"\b[A-Z]{2}\d{6}[A-Z]\b",
                frozenset({"nino", "national insurance", "ni number", "uk"}),
                0.90,
                SensitiveCategory.IDENTITY_INTL,
                None,
            ),
            (
                "CA_SOCIAL_INS",
                r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b",
                frozenset({"sin", "social insurance", "canada", "canadian"}),
                0.89,
                SensitiveCategory.IDENTITY_INTL,
                None,
            ),
            (
                "FR_INSEE_NUM",
                r"\b[12]\d{2}[01]\d\d{8}\d{2}\b",
                frozenset({"insee", "sécurité sociale", "france", "numéro"}),
                0.88,
                SensitiveCategory.IDENTITY_INTL,
                None,
            ),
            (
                "DE_STEUER_ID",
                r"\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b",
                frozenset({"steuer", "steuernummer", "finanzamt", "deutschland"}),
                0.87,
                SensitiveCategory.IDENTITY_INTL,
                None,
            ),
            (
                "TR_TCID",
                r"\b[1-9]\d{9}[02468]\b",
                frozenset({"tc", "kimlik", "vatandaşlık", "nüfus", "türkiye"}),
                0.92,
                SensitiveCategory.IDENTITY_INTL,
                "tcid",
            ),
            (
                "SA_NATIONAL_ID",
                r"\b1\d{9}\b",
                frozenset({"هوية", "رقم الهوية", "saudi", "وطنية", "identity"}),
                0.91,
                SensitiveCategory.IDENTITY_INTL,
                "saudi_nid",
            ),
            (
                "UAE_EMIRATES_ID",
                r"\b784-\d{4}-\d{7}-\d\b",
                frozenset({"emirates", "هوية", "uae", "emirati", "identity"}),
                0.93,
                SensitiveCategory.IDENTITY_INTL,
                "luhn",
            ),

            # ── CORPORATE ─────────────────────────────────────────────────
            (
                "CORP_EMPLOYEE_ID",
                r"(?i)\b(?:EMP|EMPLOYEE|ID)[:\s]?[A-Z0-9]{5,10}\b",
                frozenset({"employee", "staff", "personnel", "worker"}),
                0.55,
                SensitiveCategory.CORPORATE,
                None,
            ),
        ]

        for entry in raw:
            type_name, regex_str, terms, risk, cat, vtag = entry
            if restrict is not None and cat not in restrict:
                continue
            self._catalogue[type_name] = PatternDescriptor(
                compiled_re=re.compile(regex_str),
                proximity_terms=terms,
                base_risk=risk,
                category=cat,
                validator_tag=vtag,
            )
