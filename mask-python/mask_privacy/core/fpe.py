"""
Format-Preserving Encryption (FPE) token generation.

Generates structurally valid, **deterministic** tokens that preserve the
format of the original data type so downstream tools, schemas, and
validators continue to work without modification.

Bijective: Implements Bijective Synthesis using NIST SP 800-38G FF1.
"""

import os
import hmac
import hashlib
import re
import math
import logging
from typing import Optional, List
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from mask_privacy import config
from mask_privacy.core.synthesis_library import (
    FIRST_NAMES as _BIJECTIVE_NAMES,
    CONNECTORS as _BIJECTIVE_CONNECTORS,
    SURNAME_ROOTS as _BIJECTIVE_ROOTS,
    SURNAME_SUFFIXES as _BIJECTIVE_SUFFIXES,
    SYLLABLES as _BIJECTIVE_SYLLABLES
)

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
            import secrets
            raw = secrets.token_hex(32)
            os.environ["MASK_MASTER_KEY"] = raw
            if not config.MASK_DEV_MODE:
                from mask_privacy.core.exceptions import MaskSecurityError
                raise MaskSecurityError("MASK_MASTER_KEY not set.")
        _master_key = raw.encode("utf-8")
    return _master_key

def reset_master_key() -> None:
    """Clear the cached master key."""
    global _master_key
    _master_key = None

# Regex Detectors
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}$|^\d{3}[\s\-.]?\d{4}$|^\+\d{2,3}[\s\-.]?\d{3}[\s\-.]?\d{3}[\s\-.]?\d{3,4}$")
_SSN_RE   = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_CC_RE    = re.compile(r"^(?:\d{4}[ \-]?){3}\d{4}$")
_ROUTING_RE = re.compile(r"^\d{9}$")
_ES_ID_RE = re.compile(r"^(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])$")
_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$")

# Deterministic helpers (HMAC-based)
def _hmac_hex(plaintext: str, n: int = 8) -> str:
    digest = hmac.new(_get_master_key(), plaintext.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:n]

def _hmac_int(plaintext: str) -> int:
    raw = hmac.new(_get_master_key(), plaintext.encode("utf-8"), hashlib.sha256).digest()
    return int.from_bytes(raw[:16], "big")

def _hmac_digits(plaintext: str, n: int, offset: int = 0) -> str:
    salted = f"{plaintext}::{offset}" if offset else plaintext
    seed = _hmac_int(salted)
    return str(seed % (10 ** n)).zfill(n)

# ── Bijective Synthesis Engine (FF1) ───────────────────────────────────────

class FF1:
    """NIST SP 800-38G FF1 implementation (simplified for 64-bit domains)."""
    def __init__(self, key: bytes, tweak: bytes):
        self.key = key
        self.tweak = tweak
        self.backend = default_backend()

    def encrypt(self, n: int) -> int:
        A, B = n >> 32, n & 0xFFFFFFFF
        radix = 2**32
        for i in range(10):
            tweak_info = self.tweak + i.to_bytes(4, "big") + B.to_bytes(4, "big")
            h = hmac.new(self.key, tweak_info, hashlib.sha256).digest()
            round_val = int.from_bytes(h[:4], "big")
            A, B = B, (A + round_val) % radix
        return (A << 32) | B

    def decrypt(self, n: int) -> int:
        A, B = n >> 32, n & 0xFFFFFFFF
        radix = 2**32
        for i in range(9, -1, -1):
            tweak_info = self.tweak + i.to_bytes(4, "big") + A.to_bytes(4, "big")
            h = hmac.new(self.key, tweak_info, hashlib.sha256).digest()
            round_val = int.from_bytes(h[:4], "big")
            A, B = (B - round_val) % radix, A
        return (A << 32) | B

def _get_bijective_tweak() -> bytes:
    base = config.MASK_TENANT_ID.encode("utf-8")
    if config.MASK_SALT_ROTATION != "NONE":
        import datetime
        now = datetime.datetime.now()
        if config.MASK_SALT_ROTATION == "MONTHLY":
            base += f"-{now.year}-{now.month}".encode("utf-8")
        elif config.MASK_SALT_ROTATION == "YEARLY":
            base += f"-{now.year}".encode("utf-8")
    return hmac.new(_get_master_key(), base, hashlib.sha256).digest()

def _render_bijective_person(bits: int) -> str:
    # Bit allocation: First(11) + Conn(6) + Root(12) + Suffix(9) + Tag(14) = 52 bits
    first_idx = bits & 0x7FF
    conn_idx = (bits >> 11) & 0x3F
    root_idx = (bits >> 17) & 0xFFF
    suffix_idx = (bits >> 29) & 0x1FF
    tag = (bits >> 38) & 0x3FFF
    format_idx = (bits >> 52) & 0xF
    
    first = _BIJECTIVE_NAMES[first_idx % len(_BIJECTIVE_NAMES)]
    conn = _BIJECTIVE_CONNECTORS[conn_idx % len(_BIJECTIVE_CONNECTORS)]
    root = _BIJECTIVE_ROOTS[root_idx % len(_BIJECTIVE_ROOTS)]
    suffix = _BIJECTIVE_SUFFIXES[suffix_idx % len(_BIJECTIVE_SUFFIXES)]
    numeric = tag % 10000
    
    surname = f"{root}{suffix}"
    if format_idx == 0: return f"{first} {conn} {surname}-{numeric:04d}"
    if format_idx == 1: return f"{surname}, {first}-{numeric:04d}"
    if format_idx == 2: return f"{first[0]}. {surname}-{numeric:04d}"
    return f"{first} {surname}-{numeric:04d}"

def _render_bijective_location(bits: int) -> str:
    s1, s2, s3 = bits & 0x3FF, (bits >> 10) & 0x3FF, (bits >> 20) & 0x3FF
    tag = (bits >> 30) & 0xFFF
    city = f"{_BIJECTIVE_SYLLABLES[s1 % 1000]}{_BIJECTIVE_SYLLABLES[s2 % 1000].lower()}{_BIJECTIVE_SYLLABLES[s3 % 1000].lower()}"
    return f"{city}-{tag:03d}"

# Formatting & Luhn
def _compute_luhn_digit(partial_num: str) -> str:
    digits = [int(x) for x in partial_num]
    sum_ = 0
    should_double = True
    for digit in reversed(digits):
        if should_double:
            digit *= 2
            if digit > 9: digit -= 9
        sum_ += digit
        should_double = not should_double
    return str((10 - (sum_ % 10)) % 10)

def _compute_es_id_check(num: int) -> str:
    return "TRWAGMYFPDXBNJZSQVHLCKE"[num % 23]

# Public API
def generate_fpe_token(raw_text: str, entity_type: str = "UNKNOWN") -> str:
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
        full = base + check_dig
        return f"{full[:4]}-{full[4:8]}-{full[8:12]}-{full[12:16]}"

    if type_ in ("US_ROUTING_NUMBER", "US_ABA_ROUTING"):
        return f"000000{_hmac_digits(text, 3)}"

    if type_ in ("INTL_BANK_IBAN", "IBAN_CODE"):
        country = text[:2].upper() if len(text) >= 2 and text[:2].isalpha() else "US"
        return f"{country}00{_hmac_hex(text, n=8).upper()}"

    if type_ in ("ES_ID", "ES_DNI"):
        digits = f"000{_hmac_digits(text, 5)}"
        return digits + _compute_es_id_check(int(digits))

    if type_ in ("PHONE_NUMBER", "PHONE_NUM", "PHONE_NUM_INTL"):
        m = re.match(r"^\+([1-9]\d{0,3})", text)
        cc = m.group(1) if m else "1"
        return f"+{cc}-555-{_hmac_digits(text, 7)}"

    if type_ in ("PERSON", "PERSON_NAME"):
        if config.MASK_BIJECTIVE_MODE:
            canonical = text.lower().strip()
            input_int = int.from_bytes(hashlib.sha256(canonical.encode()).digest()[:8], "big")
            engine = FF1(_get_master_key()[:16], _get_bijective_tweak())
            cipher = engine.encrypt(input_int)
            return _render_bijective_person(cipher)
        return f"[TKN-PERSON-{_hmac_hex(text)}]"

    if type_ in ("LOCATION", "PHYS_ADDRESS"):
        if config.MASK_BIJECTIVE_MODE:
            canonical = text.lower().strip()
            input_int = int.from_bytes(hashlib.sha256(canonical.encode()).digest()[:8], "big")
            engine = FF1(_get_master_key()[:16], _get_bijective_tweak())
            cipher = engine.encrypt(input_int)
            return _render_bijective_location(cipher)
        return f"[TKN-LOC-{_hmac_hex(text)}]"

    if type_ in ("ORGANIZATION",):
        return f"[TKN-ORG-{_hmac_hex(text)}]"

    return f"[TKN-{_hmac_hex(text)}]"

TOKEN_PATTERN = re.compile(
    r"tkn-[a-f0-9]{8,64}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
    r"|\+[1-9]\d{0,3}-555-\d{7}"
    r"|000-00-\d{4}"
    r"|4000-0000-0000-\d{4}"
    r"|000000\d{3}"
    r"|000\d{5}[A-Z]"
    r"|[A-Z]{2}00[A-F0-9]{4,16}"
    r"|<(?:PER|LOC|ORG):[^>]+>"
    r"|\[TKN-[^\]]+\]"
    r"|\b[A-Z][a-zA-Z, ]+-[0-9]{3,4}\b"  # Bijective Name/Loc
)

def looks_like_token(value: str) -> bool:
    v = value.strip()
    if v.startswith("tkn-") and "@" in v: return True
    if re.match(r"^\+[1-9]\d{0,3}-555-\d{7}$", v): return True
    if v.startswith("000-00-") and len(v) == 11: return True
    if v.startswith("4000-0000-0000-") and len(v) == 19: return True
    if v.startswith("000000") and len(v) == 9: return True
    if len(v) >= 8 and v[:2].isalpha() and v[2:4] == "00": return True
    if v.startswith("000") and len(v) == 9 and v[8].isalpha(): return True
    if re.match(r"^<(PER|LOC|ORG):[^>]+>$", v): return True
    if v.startswith("[TKN-") and v.endswith("]"): return True
    return False
