import os
import hmac
import hashlib
import re
import logging
from typing import Optional, List

from mask_privacy import config
from mask_privacy.core.ff1 import FF1
from mask_privacy.core.synthesis_library import (
    FIRST_NAMES as _BIJECTIVE_NAMES,
    CONNECTORS as _BIJECTIVE_CONNECTORS,
    SURNAME_ROOTS as _BIJECTIVE_ROOTS,
    SURNAME_SUFFIXES as _BIJECTIVE_SUFFIXES,
    SYLLABLES as _BIJECTIVE_SYLLABLES
)

logger = logging.getLogger("mask.fpe")

# Master key management

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

def _get_aes_key() -> bytes:
    # Ensure exactly 32 bytes for FF1 AES-256
    return hashlib.sha256(_get_master_key()).digest()

# Regex Detectors
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}$|^\d{3}[\s\-.]?\d{4}$|^\+\d{2,3}[\s\-.]?\d{3}[\s\-.]?\d{3}[\s\-.]?\d{3,4}$")
_SSN_RE   = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_CC_RE    = re.compile(r"^(?:\d{4}[ \-]?){3}\d{4}$")
_ROUTING_RE = re.compile(r"^\d{9}$")
_ES_ID_RE = re.compile(r"^(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])$")
_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$")

def _hmac_hex(plaintext: str, n: int = 8) -> str:
    digest = hmac.new(_get_master_key(), plaintext.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:n]


# ── Bijective Synthesis Engine ─────────────────────────────────

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

def _encrypt_bijective_ff1(text: str) -> int:
    canonical = text.lower().strip()
    # Hash to 64-bit int, then to 20-digit string
    input_str = str(int.from_bytes(hashlib.sha256(canonical.encode()).digest()[:8], "big")).zfill(20)
    engine = FF1(_get_aes_key(), _get_bijective_tweak(), 10)
    cipher_str = engine.encrypt(input_str)
    return int(cipher_str) % (2**64)

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

def _strip_cc_separators(text: str) -> str:
    return re.sub(r"[\s\-]", "", text)

# Public API
def generate_dp_token(raw_text: str, entity_type: str = "UNKNOWN") -> str:
    """Generate a deterministic, format-preserving pseudonymization token using NIST FF1.
    """
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
        # Pure FF1 FPE over all 9 digits
        digits = text.replace("-", "")
        if len(digits) == 9 and digits.isdigit():
            engine = FF1(_get_aes_key(), b"US_SSN", 10)
            enc = engine.encrypt(digits)
            return f"{enc[:3]}-{enc[3:5]}-{enc[5:9]}"
        
    if type_ in ("CREDIT_CARD", "CREDIT_CARD_NUMBER"):
        digits = _strip_cc_separators(text)
        if len(digits) == 16:
            bin6 = digits[:6]
            last4 = digits[12:16]
            middle6 = digits[6:12]
            engine = FF1(_get_aes_key(), b"CREDIT_CARD", 10)
            enc_middle = engine.encrypt(middle6)
            base15 = bin6 + enc_middle + last4[:3]  # 15 digits for Luhn input
            check = _compute_luhn_digit(base15)
            full = bin6 + enc_middle + last4[:3] + check
            return f"{full[:4]}-{full[4:8]}-{full[8:12]}-{full[12:16]}"
        else:
            # Fallback length
            fallback_digits = digits.ljust(16, "0")[:16]
            engine = FF1(_get_aes_key(), b"CREDIT_CARD", 10)
            enc_middle = engine.encrypt(fallback_digits[6:12])
            full = fallback_digits[:6] + enc_middle + fallback_digits[12:]
            return f"{full[:4]}-{full[4:8]}-{full[8:12]}-{full[12:16]}"

    if type_ in ("US_ROUTING_NUMBER", "US_ABA_ROUTING"):
        if len(text) == 9 and text.isdigit():
            engine = FF1(_get_aes_key(), b"US_ROUTING", 10)
            enc = engine.encrypt(text)
            return enc

    if type_ in ("INTL_BANK_IBAN", "IBAN_CODE"):
        country = text[:2].upper() if len(text) >= 2 and text[:2].isalpha() else "US"
        return f"{country}00{_hmac_hex(text, n=8).upper()}"

    if type_ in ("ES_ID", "ES_DNI"):
        digits = re.sub(r"[A-Z]", "", text.upper())
        if digits:
            digits = digits.zfill(8)
            engine = FF1(_get_aes_key(), b"ES_ID", 10)
            enc = engine.encrypt(digits[-5:])
            token_digits = f"000{enc}"
            return token_digits + _compute_es_id_check(int(token_digits))

    if type_ in ("PHONE_NUMBER", "PHONE_NUM", "PHONE_NUM_INTL"):
        m = re.match(r"^\+([1-9]\d{0,3})", text)
        cc = m.group(1) if m else "1"
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 7:
            last7 = digits[-7:]
            engine = FF1(_get_aes_key(), b"PHONE", 10)
            enc = engine.encrypt(last7)
            return f"+{cc}-555-{enc}"

    if type_ in ("PERSON", "PERSON_NAME"):
        if config.MASK_BIJECTIVE_MODE:
            cipher_bits = _encrypt_bijective_ff1(text)
            return _render_bijective_person(cipher_bits)
        return f"[TKN-PERSON-{_hmac_hex(text)}]"

    if type_ in ("LOCATION", "PHYS_ADDRESS"):
        if config.MASK_BIJECTIVE_MODE:
            cipher_bits = _encrypt_bijective_ff1(text)
            return _render_bijective_location(cipher_bits)
        return f"[TKN-LOC-{_hmac_hex(text)}]"

    if type_ in ("ORGANIZATION",):
        return f"[TKN-ORG-{_hmac_hex(text)}]"

    return f"[TKN-{_hmac_hex(text)}]"

generate_fpe_token = generate_dp_token

TOKEN_PATTERN = re.compile(
    r"tkn-[a-f0-9]{8,64}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
    r"|\+[1-9]\d{0,3}-555-\d{7}"
    r"|\d{3}-\d{2}-\d{4}"          
    r"|\d{4}-\d{4}-\d{4}-\d{4}"   
    r"|\b\d{9}\b"                       
    r"|\b000\d{5}[A-Z]\b"              
    r"|[A-Z]{2}00[A-F0-9]{4,16}"  
    r"|<(?:PER|LOC|ORG):[^>]+>"
    r"|\[TKN-[^\]]+\]"
    r"|\b[A-Z][a-zA-Z, ]+-[0-9]{3,4}\b"  
)

def looks_like_token(value: str) -> bool:
    v = value.strip()
    if v.startswith("tkn-") and "@" in v: return True
    if re.match(r"^\+[1-9]\d{0,3}-555-\d{7}$", v): return True
    if re.match(r"^\d{3}-\d{2}-\d{4}$", v): return True
    if re.match(r"^\d{4}-\d{4}-\d{4}-\d{4}$", v): return True
    if len(v) == 9 and v.isdigit(): return True
    if len(v) >= 8 and v[:2].isalpha() and v[2:4] == "00": return True
    if re.match(r"^000\d{5}[A-Z]$", v): return True
    if re.match(r"^<(PER|LOC|ORG):[^>]+>$", v): return True
    if v.startswith("[TKN-") and v.endswith("]"): return True
    if re.match(r"^[A-Z][a-zA-Z, ]+-[0-9]{3,4}$", v): return True
    return False
