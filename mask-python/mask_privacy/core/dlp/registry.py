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
    is_high_entropy: bool             # Should we always run this even in other locales?
    supported_locales: List[str]      # Which locales is this specific to? ["*"] for global.
    rule_id: str                      # Unique ID for compliance audit trail (e.g. "MASK-FIN-001")
    compliance_scope: FrozenSet[str]  # Compliance frameworks: {"PCI-DSS", "HIPAA", "GDPR", ...}


# ── Locale-specific auxiliary patterns ────────────────────────────────────────

LOCALE_NAME_RULES: Dict[str, List[re.Pattern]] = {
    "en": [
        re.compile(r"\b[A-Z][a-z\-\']+ [A-Z][a-z\-\']+(?:\s+[A-Z][a-z\-\']+)?\b"),
        re.compile(r"\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z\-\']+\b"),
    ],
    "es": [
        re.compile(r"\b[A-Z][a-záéíóúñ\-\']+ [A-Z][a-záéíóúñ\-\']+(?:\s+[A-Z][a-záéíóúñ\-\']+)?\b"),
        re.compile(r"\b(?:Sr|Sra|Srta)\.?\s+[A-Z][a-záéíóúñ\-\']+\b"),
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
    "es": [
        re.compile(r"\b(?:Calle|Carrera|Avenida|Paseo|Plaza)\s+[A-ZÀ-ÖØ-Ý][a-zà-öø-ÿ]+\b", re.IGNORECASE),
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
        # Pre-compiled category mega-regexes (built per locale).
        # Each category maps to a List of compiled patterns — at most two:
        # index 0 = case-sensitive group, index 1 = case-insensitive group.
        # Keeping them separate prevents IGNORECASE from bleeding across
        # unrelated patterns compiled into the same alternation.
        self._locale_category_regexes: Dict[str, Dict[str, List[re.Pattern]]] = {}
        self._locale_category_type_maps: Dict[str, Dict[str, List[str]]] = {}
        # We pre-compile only the "Global" and "Common" locales on start
        for loc in ["*", "en", "es"]:
            self._compile_for_locale(loc)
        _log.info(
            "DLP registry loaded %d pattern(s) across %d locale(s)",
            len(self._catalogue),
            len(self._locale_category_regexes),
        )

    # ── public helpers ────────────────────────────────────────────────────

    @property
    def type_names(self) -> List[str]:
        return list(self._catalogue.keys())

    def get_category_regexes(self, locale: str = "en") -> Dict[str, List[re.Pattern]]:
        """Return the pre-compiled per-category Mega-Regexes for a locale.

        Returns a ``Dict[category_key, List[re.Pattern]]`` where each list
        contains at most two entries: one for case-sensitive patterns and one
        for case-insensitive patterns.  Keeping them separate prevents
        IGNORECASE from bleeding across patterns that must stay case-sensitive.

        If the locale isn't pre-compiled yet, it is built on demand.
        """
        if locale not in self._locale_category_regexes:
            self._compile_for_locale(locale)
        return self._locale_category_regexes[locale]

    def get_category_type_map(self, category_name: str, locale: str = "en") -> List[str]:
        """Return ordered list of type names in a category regex."""
        return self._locale_category_type_maps.get(locale, {}).get(category_name, [])

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

    # ── internal mega-regex compiler ──────────────────────────────────────

    def _compile_for_locale(self, locale: str) -> None:
        """Build compiled regexes per SensitiveCategory for a specific locale.

        To prevent case-flag bleed, each category bucket is split into two
        independent sub-groups before combination:

          - **case-sensitive** patterns (no IGNORECASE flag)
          - **case-insensitive** patterns (have IGNORECASE flag)

        Each sub-group is compiled as its own alternation regex, and both are
        stored in a ``List[re.Pattern]``.  The scanner iterates the list so
        that the correct flags are always applied per sub-group.
        """
        # Filter patterns valid for this locale
        locale_pool: Dict[str, List[tuple]] = {}
        for type_name, desc in self._catalogue.items():
            if "*" in desc.supported_locales or locale in desc.supported_locales:
                cat_key = desc.category.value
                locale_pool.setdefault(cat_key, []).append((type_name, desc))

        self._locale_category_regexes[locale] = {}
        self._locale_category_type_maps[locale] = {}

        for cat_key, entries in locale_pool.items():
            # Sort by specificity (validator-backed first, then by pattern length)
            entries.sort(
                key=lambda e: (
                    0 if e[1].validator_tag else 1,
                    -len(e[1].compiled_re.pattern),
                )
            )

            # Partition into case-sensitive and case-insensitive sub-groups
            cs_parts: List[str] = []   # case-sensitive
            ci_parts: List[str] = []   # case-insensitive
            type_order: List[str] = []

            for type_name, desc in entries:
                raw = desc.compiled_re.pattern
                named = f"(?P<{type_name}>{raw})"
                if desc.compiled_re.flags & re.IGNORECASE:
                    ci_parts.append(named)
                else:
                    cs_parts.append(named)
                type_order.append(type_name)

            compiled: List[re.Pattern] = []
            for group_parts, flags in ((cs_parts, 0), (ci_parts, re.IGNORECASE)):
                if not group_parts:
                    continue
                combined = "|".join(group_parts)
                try:
                    compiled.append(re.compile(combined, flags=flags))
                except re.error as exc:
                    _log.error(
                        "Failed to compile %s category regex for '%s' (locale '%s'): %s",
                        "case-insensitive" if flags else "case-sensitive",
                        cat_key, locale, exc,
                    )

            if compiled:
                self._locale_category_regexes[locale][cat_key] = compiled
                self._locale_category_type_maps[locale][cat_key] = type_order


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
                r"(?<!\d)(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)",
                frozenset({"ssn", "social security", "tax id", "taxpayer"}),
                0.95,
                SensitiveCategory.FINANCIAL,
                "ssn_area",
                None, None,  # entropy, locales (defaults)
                "MASK-FIN-001",
                frozenset({"PCI-DSS", "HIPAA", "SOC2"}),
            ),
            (
                "CREDIT_CARD_NUMBER",
                r"(?<!\d)(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}(?!\d)",
                frozenset({"card", "credit", "visa", "mastercard", "amex", "payment", "tarjeta", "credito", "debito", "pago"}),
                0.97,
                SensitiveCategory.FINANCIAL,
                "luhn",
                None, None,
                "MASK-FIN-002",
                frozenset({"PCI-DSS"}),
            ),
            (
                "INTL_BANK_IBAN",
                r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b",
                frozenset({"iban", "swift", "sepa", "wire", "bank transfer", "cuenta", "banco", "transferencia"}),
                0.96,
                SensitiveCategory.FINANCIAL,
                "iban",
                None, None,
                "MASK-FIN-003",
                frozenset({"PCI-DSS", "GDPR"}),
            ),
            (
                "CRYPTO_BTC",
                r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b",
                frozenset({"bitcoin", "btc", "wallet", "crypto"}),
                0.94,
                SensitiveCategory.FINANCIAL,
                "btc_format",
                None, None,
                "MASK-FIN-004",
                frozenset({"SOC2"}),
            ),
            (
                "CRYPTO_ETH",
                r"\b0x[a-fA-F0-9]{40}\b",
                frozenset({"ethereum", "eth", "wallet", "0x"}),
                0.93,
                SensitiveCategory.FINANCIAL,
                None,
                None, None,
                "MASK-FIN-005",
                frozenset({"SOC2"}),
            ),
            (
                "US_ABA_ROUTING",
                r"(?<!\d)\d{9}(?!\d)",
                frozenset({"routing", "aba", "wire", "bank"}),
                0.88,
                SensitiveCategory.FINANCIAL,
                "aba_check",
                None, None,
                "MASK-FIN-006",
                frozenset({"PCI-DSS", "SOC2"}),
            ),
            (
                "BANK_ACCT_NUM",
                r"(?<!\d)\d{8,17}(?!\d)",
                frozenset({"account", "checking", "savings", "deposit", "bank"}),
                0.50,
                SensitiveCategory.FINANCIAL,
                "luhn_soft",
                None, None,
                "MASK-FIN-007",
                frozenset({"PCI-DSS", "SOC2"}),
            ),
            (
                "ES_CCC",
                r"\b\d{4}[-\s]?\d{4}[-\s]?\d{2}[-\s]?\d{10}\b",
                frozenset({"cuenta", "ccc", "banco", "sucursal", "entidad", "codigo cuenta cliente"}),
                0.90,
                SensitiveCategory.FINANCIAL,
                "es_ccc",
                True,
                ["*", "es"],
                "MASK-FIN-008",
                frozenset({"GDPR"}),
            ),
            (
                "SWIFT_BIC",
                r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
                frozenset({"swift", "bic", "bank code", "transfer"}),
                0.60,
                SensitiveCategory.FINANCIAL,
                None,
                None, None,
                "MASK-FIN-009",
                frozenset({"PCI-DSS"}),
            ),

            # ── CONTACT ───────────────────────────────────────────────────
            (
                "EMAIL_ADDR",
                r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
                frozenset({"email", "mail", "contact", "address", "correo", "electronico"}),
                0.99,
                SensitiveCategory.CONTACT,
                None,
                None, None,
                "MASK-CTX-001",
                frozenset({"GDPR", "HIPAA", "SOC2"}),
            ),
            (
                "PHONE_NUM",
                r"(?<!\d)(?:\+?[1-9]\d{0,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}(?!\d)",
                frozenset({"phone", "call", "mobile", "tel", "whatsapp", "number", "teléfono", "telefono", "movil", "celular", "llamada"}),
                0.80,
                SensitiveCategory.CONTACT,
                None,
                None, None,
                "MASK-CTX-002",
                frozenset({"GDPR", "HIPAA", "SOC2"}),
            ),
            (
                "PHONE_NUM_INTL",
                r"(?<!\d)\+(?:[1-9]\d{0,3})[-.\s]?\(?\d{1,5}\)?(?:[-.\s]?\d{2,4}){2,4}(?!\d)",
                frozenset({"phone", "call", "mobile", "tel"}),
                0.80,
                SensitiveCategory.CONTACT,
                None,
                None, None,
                "MASK-CTX-003",
                frozenset({"GDPR", "SOC2"}),
            ),
            (
                "IPV4_ADDR",
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
                frozenset({"ip", "server", "host", "network", "address"}),
                0.94,
                SensitiveCategory.CONTACT,
                "ipv4",
                None, None,
                "MASK-CTX-004",
                frozenset({"GDPR", "SOC2"}),
            ),
            (
                "IPV6_ADDR",
                r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",
                frozenset({"ipv6", "ip", "network", "server"}),
                0.93,
                SensitiveCategory.CONTACT,
                None,
                None, None,
                "MASK-CTX-005",
                frozenset({"GDPR", "SOC2"}),
            ),
            (
                "HW_MAC_ADDR",
                r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
                frozenset({"mac", "hardware", "network", "device"}),
                0.91,
                SensitiveCategory.CONTACT,
                None,
                None, None,
                "MASK-CTX-006",
                frozenset({"SOC2"}),
            ),

            # ── PERSONAL ──────────────────────────────────────────────────
            (
                "BIRTH_DATE",
                r"\b(?:(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}|(?:19|20)\d{2}[/-](?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01]))\b",
                frozenset({"birth", "dob", "born", "birthday", "date of birth", "nacimiento", "fecha", "cumpleaños"}),
                0.88,
                SensitiveCategory.PERSONAL,
                None,
                None, None,
                "MASK-PER-001",
                frozenset({"GDPR", "HIPAA"}),
            ),
            (
                "US_DRIVERS_LIC",
                r"\b(?:[A-Z]\d{7,12}|\d{7,12}[A-Z]?)\b",
                frozenset({"driver", "license", "licence", "dl", "dmv"}),
                0.55,
                SensitiveCategory.PERSONAL,
                None,
                None, None,
                "MASK-PER-002",
                frozenset({"GDPR", "SOC2"}),
            ),
            (
                "US_PASSPORT_NUM",
                r"\b[A-Z]\d{8}\b",
                frozenset({"passport", "travel", "visa", "immigration"}),
                0.87,
                SensitiveCategory.PERSONAL,
                None,
                None, None,
                "MASK-PER-003",
                frozenset({"GDPR", "SOC2"}),
            ),

            # ── VEHICLE ───────────────────────────────────────────────────
            (
                "VEHICLE_VIN",
                r"\b[A-HJ-NPR-Z0-9]{17}\b",
                frozenset({"vin", "vehicle", "chassis", "automobile"}),
                0.92,
                SensitiveCategory.VEHICLE,
                "vin_format",
                None, None,
                "MASK-VEH-001",
                frozenset({"SOC2"}),
            ),
            (
                "VEHICLE_PLATE",
                r"\b[A-Z0-9]{1,3}[\-\s][A-Z0-9]{1,4}[\-\s][A-Z0-9]{1,4}\b",
                frozenset({"plate", "registration", "vehicle", "plaka"}),
                0.45,
                SensitiveCategory.VEHICLE,
                None,
                None, None,
                "MASK-VEH-002",
                frozenset({"SOC2"}),
            ),

            # ── HEALTHCARE ────────────────────────────────────────────────
            (
                "MED_RECORD_ID",
                r"\b(?:MRN|Patient ID|Medical Record)[:\s]*[A-Z0-9]{6,10}\b",
                frozenset({"patient", "medical", "record", "mrn", "hospital"}),
                0.96,
                SensitiveCategory.HEALTHCARE,
                None,
                None, None,
                "MASK-HLT-001",
                frozenset({"HIPAA"}),
            ),
            (
                "US_MEDICARE_ID",
                r"\b\d{3}-\d{2}-\d{4}[A-Z]\b",
                frozenset({"medicare", "cms", "beneficiary", "health insurance"}),
                0.91,
                SensitiveCategory.HEALTHCARE,
                None,
                None, None,
                "MASK-HLT-002",
                frozenset({"HIPAA"}),
            ),
            (
                "US_DEA_NUM",
                r"\b[A-Z]{2}\d{7}\b",
                frozenset({"dea", "prescriber", "drug", "enforcement"}),
                0.89,
                SensitiveCategory.HEALTHCARE,
                None,
                None, None,
                "MASK-HLT-003",
                frozenset({"HIPAA"}),
            ),
            (
                "US_NPI_NUM",
                r"\b\d{10}\b",
                frozenset({"npi", "provider", "national provider", "healthcare"}),
                0.87,
                SensitiveCategory.HEALTHCARE,
                None,
                None, None,
                "MASK-HLT-004",
                frozenset({"HIPAA"}),
            ),

            # ── IDENTITY_US ───────────────────────────────────────────────
            (
                "US_EIN_TAX",
                r"\b\d{2}-\d{7}\b",
                frozenset({"ein", "federal", "employer", "tax id"}),
                0.89,
                SensitiveCategory.IDENTITY_US,
                None,
                None, None,
                "MASK-IDU-001",
                frozenset({"SOC2"}),
            ),

            # ── IDENTITY_INTL ─────────────────────────────────────────────
            (
                "UK_NATL_INS",
                r"\b[A-Z]{2}\d{6}[A-Z]\b",
                frozenset({"nino", "national insurance", "ni number", "uk"}),
                0.90,
                SensitiveCategory.IDENTITY_INTL,
                "uk_nino",
                None, None,
                "MASK-IDI-001",
                frozenset({"GDPR"}),
            ),
            (
                "CA_SOCIAL_INS",
                r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b",
                frozenset({"sin", "social insurance", "canada", "canadian"}),
                0.89,
                SensitiveCategory.IDENTITY_INTL,
                "ca_sin",
                None, None,
                "MASK-IDI-002",
                frozenset({"SOC2"}),
            ),
            (
                "ES_DNI",
                r"\b(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b",
                frozenset({"dni", "nie", "identidad", "nif", "spain"}),
                0.94,
                SensitiveCategory.IDENTITY_INTL,
                "es_id",
                True,
                ["*", "es"],
                "MASK-IDI-003",
                frozenset({"GDPR"}),
            ),
            (
                "ES_NUSS",
                r"\b\d{2}[-\s]?\d{8}[-\s]?\d{2}\b",
                frozenset({"seguridad social", "nuss", "naf", "afiliacion"}),
                0.90,
                SensitiveCategory.IDENTITY_INTL,
                "es_nuss",
                True,
                ["*", "es"],
                "MASK-IDI-004",
                frozenset({"GDPR"}),
            ),

            # ── CORPORATE ─────────────────────────────────────────────────
            (
                "CORP_EMPLOYEE_ID",
                r"\b(?:EMP|EMPLOYEE|ID)[:\s]?[A-Z0-9]{5,10}\b",
                frozenset({"employee", "staff", "personnel", "worker"}),
                0.55,
                SensitiveCategory.CORPORATE,
                None,
                None, None,
                "MASK-CRP-001",
                frozenset({"SOC2", "GDPR"}),
            ),
        ]

        for entry in raw:
            # Handle entries with or without explicit locale/entropy/audit (backward compatibility)
            if len(entry) == 10:
                type_name, regex_str, terms, risk, cat, vtag, entropy, locales, rule_id, compliance = entry
            elif len(entry) == 8:
                type_name, regex_str, terms, risk, cat, vtag, entropy, locales = entry
                rule_id = f"MASK-{cat.value[:3]}-{type_name}"
                compliance = frozenset()
            else:
                type_name, regex_str, terms, risk, cat, vtag = entry
                entropy = True if vtag else False
                locales = ["*"]
                rule_id = f"MASK-{cat.value[:3]}-{type_name}"
                compliance = frozenset()

            # Handle None sentinel for entropy/locales in 10-tuple entries
            if entropy is None:
                entropy = True if vtag else False
            if locales is None:
                locales = ["*"]

            if restrict is not None and cat not in restrict:
                continue
            # Handle explicit case-insensitivity without breaking mega-regex compilation
            flags = 0
            if regex_str.startswith("(?i)"):
                regex_str = regex_str[4:]
                flags = re.IGNORECASE

            self._catalogue[type_name] = PatternDescriptor(
                compiled_re=re.compile(regex_str, flags=flags),
                proximity_terms=terms,
                base_risk=risk,
                category=cat,
                validator_tag=vtag,
                is_high_entropy=entropy,
                supported_locales=locales,
                rule_id=rule_id,
                compliance_scope=compliance if isinstance(compliance, frozenset) else frozenset(compliance),
            )
