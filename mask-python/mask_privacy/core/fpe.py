"""
Format-Preserving Encryption (FPE) token generation.

Generates structurally valid, **deterministic** tokens that preserve the
*format* of the original data type so downstream tools, schemas, and
validators continue to work without modification.

Determinism is achieved via HMAC-SHA256 keyed with a master key, ensuring
the same plaintext always produces the same token.  This preserves entity
relationships for LLMs (e.g. "John" is always [TKN-abc]) without leaking
the identity.

Supported formats:
  - Email  →  tkn-<hex>@email.com
  - Phone  →  +1-555-<7 digits>
  - SSN    →  000-00-<4 digits>
  - CC     →  4000-0000-0000-<4 digits>
  - Routing→  000000<3 digits>
  - Default→  [TKN-<hex>]
"""

import os
import hmac
import hashlib
import re
import logging
from typing import Optional
from mask_privacy import config

logger = logging.getLogger("mask.fpe")


# ---------------------------------------------------------------------------
# Master key management
# ---------------------------------------------------------------------------

_master_key: Optional[bytes] = None


def _get_master_key() -> bytes:
    """Return the HMAC master key, lazily initialised from the key provider."""
    global _master_key
    if _master_key is None:
        from mask_privacy.core.key_provider import get_key_provider

        raw = get_key_provider().get_master_key() or ""
        if not raw:
            # Auto-generate a session-local key (non-persistent)
            import secrets
            raw = secrets.token_hex(32)
            os.environ["MASK_MASTER_KEY"] = raw
            if not config.MASK_DEV_MODE:
                from mask_privacy.core.exceptions import MaskSecurityError
                raise MaskSecurityError(
                    "MASK_MASTER_KEY not set and MASK_DEV_MODE is not 'true'. "
                    "Refusing to proceed without an explicit key."
                )
            logger.warning(
                "MASK_MASTER_KEY not set. Using an ephemeral session key. "
                "Tokens will NOT be reproducible across process restarts."
            )
        _master_key = raw.encode("utf-8")
    return _master_key


def reset_master_key() -> None:
    """Clear the cached master key.  Useful in tests."""
    global _master_key
    _master_key = None

# Detectors — order matters: first match wins


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(
    r"^\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}$"
    r"|^\d{3}[\s\-.]?\d{4}$"
)
_SSN_RE   = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_CC_RE    = re.compile(r"^(?:\d{4}[ \-]?){3}\d{4}$")
_ROUTING_RE = re.compile(r"^\d{9}$")

# International ID format detectors
_ES_ID_RE = re.compile(r"^(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])$")
_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$") # IBAN


# Deterministic helpers (HMAC-based)

def _hmac_hex(plaintext: str, n: int = 8) -> str:
    """Return *n* deterministic hex characters derived from HMAC(key, plaintext)."""
    digest = hmac.new(
        _get_master_key(), plaintext.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return digest[:n]


def _hmac_digits(plaintext: str, n: int, offset: int = 0) -> str:
    """Return *n* deterministic decimal digits derived from HMAC(key, plaintext).

    *offset* shifts the window into the digest to avoid collisions when
    multiple digit fields are derived from the same plaintext.
    """
    digest = hmac.new(
        _get_master_key(), plaintext.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    # Convert hex nibbles to digits via modulo-10
    result = []
    for ch in digest[offset:]:
        result.append(str(int(ch, 16) % 10))
        if len(result) == n:
            break
    # Safety: pad with zeros if digest is too short (shouldn't happen for SHA-256)
    while len(result) < n:
        result.append("0")
    return "".join(result)


# Public API

# Dictionary for Semantic NLP Faker Generation
_FIRST_NAMES = ["Taylor", "Jordan", "Casey", "Morgan", "Riley", "Avery", "Rowan", "Quinn", "Charlie", "Peyton", "Blake", "Dakota", "Reese", "Skyler", "Finley", "Eden", "Harley", "Rory", "Emerson", "Remi"]
_LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"]
_CITIES = ["London", "Paris", "Berlin", "Tokyo", "Rome", "Madrid", "Vienna", "Sydney", "Toronto", "Chicago", "Seattle", "Austin", "Boston", "Denver", "Dallas", "Miami", "Seoul", "Dubai", "Mumbai", "Cairo"]

def _pick_from_array(plaintext: str, array: list[str]) -> str:
    digits = _hmac_digits(plaintext, 8)
    num = int(digits, 10)
    return array[num % len(array)]

def _compute_luhn_digit(partial_num: str) -> str:
    digits = [int(x) for x in partial_num]
    sum_ = 0
    should_double = True
    for digit in reversed(digits):
        if should_double:
            digit *= 2
            if digit > 9:
                digit -= 9
        sum_ += digit
        should_double = not should_double
    return str((10 - (sum_ % 10)) % 10)



def _compute_es_id_check(num: int) -> str:
    return "TRWAGMYFPDXBNJZSQVHLCKE"[num % 23]

def generate_fpe_token(raw_text: str, entity_type: str = "UNKNOWN") -> str:
    """Return a **deterministic**, format-preserving token for *raw_text*."""
    text = raw_text.strip()
    type_ = (entity_type or "UNKNOWN").upper()

    if type_ == "UNKNOWN":
        if _EMAIL_RE.match(text): type_ = "EMAIL_ADDRESS"
        elif _SSN_RE.match(text): type_ = "US_SSN"
        elif _CC_RE.match(text): type_ = "CREDIT_CARD"
        elif _ROUTING_RE.match(text): type_ = "US_ROUTING_NUMBER"
        elif _ES_ID_RE.match(text): type_ = "ES_ID"
        elif _IBAN_RE.match(text): type_ = "INTL_BANK_IBAN"
        elif _PHONE_RE.match(text): type_ = "PHONE_NUMBER"

    if type_ in ("EMAIL_ADDRESS", "EMAIL_ADDR"):
        parts = text.split("@", 1)
        domain = parts[1] if len(parts) == 2 else "email.com"
        return f"tkn-{_hmac_hex(text)}@{domain}"

    if type_ == "US_SSN":
        return f"000-00-{_hmac_digits(text, 4)}"

    if type_ in ("CREDIT_CARD", "CREDIT_CARD_NUMBER"):
        base = f"400000000000{_hmac_digits(text, 3)}"
        check_dig = _compute_luhn_digit(base)
        full = base + check_dig # 16 digits
        return f"{full[:4]}-{full[4:8]}-{full[8:12]}-{full[12:16]}"

    if type_ in ("US_ROUTING_NUMBER", "US_ABA_ROUTING"):
        return f"000000{_hmac_digits(text, 3)}"

    if type_ in ("INTL_BANK_IBAN", "IBAN_CODE"):
        country = text[:2].upper() if len(text) >= 2 and text[:2].isalpha() else "US"
        return f"{country}00{_hmac_hex(text, n=8).upper()}"

    if type_ == "ES_DNI":
        # Format: 000 + 5 digits + check letter
        digits = f"000{_hmac_digits(text, 5)}"
        return digits + _compute_es_id_check(int(digits))

    if type_ in ("PHONE_NUMBER", "PHONE_NUM", "PHONE_NUM_INTL"):
        m = re.match(r"^\+([1-9]\d{0,3})", text)
        cc = m.group(1) if m else "1"
        return f"+{cc}-555-{_hmac_digits(text, 7)}"

    if type_ in ("PERSON", "PERSON_NAME"):
        f = _pick_from_array(text, _FIRST_NAMES)
        l = _pick_from_array(text + "last", _LAST_NAMES)
        return f"<PER:{f}_{l}>"
        
    if type_ in ("LOCATION", "PHYS_ADDRESS"):
        c = _pick_from_array(text, _CITIES)
        return f"<LOC:{c}>"
        
    if type_ in ("ORGANIZATION",):
        o = _pick_from_array(text, _LAST_NAMES)
        return f"<ORG:{o}_Inc>"

    # Generic fallback
    return f"[TKN-{_hmac_hex(text)}]"


# Regex that matches ANY valid Mask token.
# Used for sub-string detokenization (finding tokens inside paragraphs).
TOKEN_PATTERN = re.compile(
    r"tkn-[a-f0-9]{8,64}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"         # Email
    r"|\+[1-9]\d{0,3}-555-\d{7}"                                # Phone
    r"|000-00-\d{4}"                            # SSN
    r"|4000-0000-0000-\d{4}"                    # CC
    r"|000000\d{3}"                             # Routing
    r"|000\d{5}[A-Z]"                           # Spanish DNI token
    r"|[A-Z]{2}00[A-F0-9]{4,16}"                # IBAN token
    r"|<(?:PER|LOC|ORG):[^>]+>"                 # Semantic NLP tokens
    r"|\[TKN-[a-f0-9]{8,64}\]"                   # Opaque
)


def looks_like_token(value: str) -> bool:
    """Heuristic: return True if *value* appears to be a Mask token.

    Safety notes on numeric tokens:
    - SSN tokens use prefix ``000-00-``. Area number ``000`` has never been
      assigned by the SSA, so no real SSN will ever match.
    - Routing tokens use prefix ``000000``. The Federal Reserve Routing Symbol
      ``0000`` is not a valid symbol (valid range starts at ``01``), so no real
      ABA routing number will ever match.
    - Credit card tokens use prefix ``4000-0000-0000-``. The BIN ``4000 00``
      is reserved for testing by Visa and is not issued to real cardholders.
    """
    v = value.strip()

    # Email tokens: tkn-<hex>@domain.com
    if v.startswith("tkn-") and "@" in v:
        prefix, domain = v.split("@", 1)
        if len(prefix) >= 12 and "." in domain:
            return True

    # Phone tokens: +CC-555-XXXXXXX  (555 is the standard fictional exchange)
    if re.match(r"^\+[1-9]\d{0,3}-555-\d{7}$", v):
        return True

    # SSN tokens: 000-00-XXXX  (area 000 is never assigned)
    if v.startswith("000-00-") and len(v) == 11 and v[7:].isdigit():
        return True

    # Credit card tokens: 4000-0000-0000-XXXX  (reserved test BIN)
    if v.startswith("4000-0000-0000-") and len(v) == 19 and v[15:].isdigit():
        return True

    # Routing tokens: 000000XXX  (invalid Fed symbol 0000)
    if v.startswith("000000") and len(v) == 9 and v[6:].isdigit():
        return True

    # IBAN tokens: XX00... (zero check digits indicate synthetic)
    if len(v) >= 8 and v[:2].isalpha() and v[2:4] == "00":
        return True

    # Spanish ID tokens
    if v.startswith("000") and len(v) == 9 and v[8].isalpha():
        return True

    # Semantic NLP tokens
    if re.match(r"^<(PER|LOC|ORG):[^>]+>$", v):
        return True

    # Opaque fallback tokens: [TKN-<hex>]
    if v.startswith("[TKN-") and v.endswith("]"):
        return True

    return False
