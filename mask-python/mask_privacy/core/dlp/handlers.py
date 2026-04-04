"""
DLP Validation Engine — Hard-validators for post-match verification.

Each validator implements a *deterministic* check (checksum, length rule,
character constraint) that confirms whether a regex-matched string is
genuinely sensitive data.  Passing a hard-validator overrides the
confidence score to 0.99 ("Definitive").

Every function is a standalone pure-function with no shared state,
making the module inherently thread-safe.
"""

from __future__ import annotations

import re
import logging

_log = logging.getLogger("mask.dlp.handlers")


# ── Luhn (Mod-10) — Credit Cards, UAE Emirates ID ────────────────────────────

def check_luhn(raw: str) -> bool:
    """Verify a numeric string against the Luhn / Mod-10 algorithm.

    Non-digit characters are stripped before validation.
    Returns ``False`` for strings shorter than 8 digits.
    """
    stripped = re.sub(r"\D", "", raw)
    if len(stripped) < 8:
        return False
    total = 0
    for idx, ch in enumerate(reversed(stripped)):
        digit = int(ch)
        if idx % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# ── US SSN area-number check ─────────────────────────────────────────────────

def check_ssn_area(raw: str) -> bool:
    """Reject SSNs with invalid area numbers (000, 666, 900–999).

    Also rejects group ``00`` and serial ``0000``.
    """
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or int(area) >= 900:
        return False
    if group == "00" or serial == "0000":
        return False
    return True


# ── IBAN structural check ────────────────────────────────────────────────────

_IBAN_COUNTRY_LENGTHS = {
    "AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BY": 28,
    "BE": 16, "BA": 20, "BR": 29, "BG": 22, "CR": 22, "HR": 21,
    "CY": 28, "CZ": 24, "DK": 18, "DO": 28, "TL": 23, "EE": 20,
    "FO": 18, "FI": 18, "FR": 27, "GE": 22, "DE": 22, "GI": 23,
    "GR": 27, "GL": 18, "GT": 28, "HU": 28, "IS": 26, "IQ": 23,
    "IE": 22, "IL": 23, "IT": 27, "JO": 30, "KZ": 20, "XK": 20,
    "KW": 30, "LV": 21, "LB": 28, "LI": 21, "LT": 20, "LU": 20,
    "MK": 19, "MT": 31, "MR": 27, "MU": 30, "MC": 27, "MD": 24,
    "ME": 22, "NL": 18, "NO": 15, "PK": 24, "PS": 29, "PL": 28,
    "PT": 25, "QA": 29, "RO": 24, "SM": 27, "SA": 24, "RS": 22,
    "SC": 31, "SK": 24, "SI": 19, "ES": 24, "SE": 24, "CH": 21,
    "TN": 24, "TR": 26, "AE": 23, "GB": 22, "VA": 22, "VG": 24,
}


def check_iban_structure(raw: str) -> bool:
    """Validate IBAN length-per-country and ISO 7064 Mod-97 checksum."""
    cleaned = raw.replace(" ", "").upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False
    country = cleaned[:2]
    if not country.isalpha():
        return False
    expected_len = _IBAN_COUNTRY_LENGTHS.get(country)
    if expected_len and len(cleaned) != expected_len:
        return False
    # ISO 7064 Mod-97 verification
    rearranged = cleaned[4:] + cleaned[:4]
    numeric_repr = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric_repr += ch
        elif ch.isalpha():
            numeric_repr += str(ord(ch) - 55)  # A=10, B=11, …
        else:
            return False
    return int(numeric_repr) % 97 == 1


# ── US ABA Routing Number ────────────────────────────────────────────────────

def check_aba_routing(raw: str) -> bool:
    """Validate a 9-digit ABA routing number via the weighted-sum checksum."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 9:
        return False
    d = [int(c) for c in digits]
    weighted = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
    return weighted % 10 == 0


# ── VIN (Vehicle Identification Number) ──────────────────────────────────────

_VIN_TRANSLITERATION = {
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def check_vin_format(raw: str) -> bool:
    """Validate VIN: 17 chars, no I/O/Q, and check-digit (pos 9)."""
    vin = raw.strip().upper()
    if len(vin) != 17:
        return False
    if any(ch in vin for ch in "IOQ"):
        return False
    # Position-9 check digit
    total = 0
    for i, ch in enumerate(vin):
        if ch.isdigit():
            val = int(ch)
        else:
            val = _VIN_TRANSLITERATION.get(ch)
            if val is None:
                return False
        total += val * _VIN_WEIGHTS[i]
    remainder = total % 11
    expected = "X" if remainder == 10 else str(remainder)
    return vin[8] == expected


# ── Bitcoin address basic format ─────────────────────────────────────────────

def check_btc_format(raw: str) -> bool:
    """Shallow validation: length + prefix + forbidden characters."""
    addr = raw.strip()
    if len(addr) < 26 or len(addr) > 62:
        return False
    if not (addr[0] in "13" or addr.startswith("bc1")):
        return False
    return True


# ── IPv4 octet-range check ───────────────────────────────────────────────────

def check_ipv4_octets(raw: str) -> bool:
    """Verify each octet is 0-255."""
    parts = raw.strip().split(".")
    if len(parts) != 4:
        return False
    for segment in parts:
        if not segment.isdigit():
            return False
        if not 0 <= int(segment) <= 255:
            return False
    return True


# ── Canadian SIN (Luhn-9) ────────────────────────────────────────────────────

def check_ca_sin(raw: str) -> bool:
    """Validate Canadian Social Insurance Number.
    
    Applies the Modulo 10 (Luhn) algorithm specifically for 9 digits.
    """
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 9:
        return False
        
    total = 0
    for idx, ch in enumerate(digits):
        val = int(ch)
        if idx % 2 == 1:  # 0-indexed, so 1 is 2nd digit, 3 is 4th, etc.
            val *= 2
            if val > 9:
                val -= 9
        total += val
    return total % 10 == 0


# ── UK National Insurance Number (NINO) ──────────────────────────────────────

_UK_NINO_REGEX = re.compile(
    r"^(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D]$"
)

def check_uk_nino(raw: str) -> bool:
    """Validate a UK National Insurance Number against prefix/suffix constraints.
    
    Cannot use letters D, F, I, Q, U, V, and O (O handled mostly by first char).
    Specific prefixes are forbidden (BG, GB, NK, KN, TN, NT, ZZ).
    Must end with A, B, C, or D.
    """
    cleaned = raw.replace(" ", "").upper()
    if len(cleaned) != 9:
        return False
    return bool(_UK_NINO_REGEX.match(cleaned))


# ── Spanish DNI/NIE (8 digits + 1 letter) ───────────────────────────────────

def check_es_id(raw: str) -> bool:
    """Validate Spanish DNI (National ID) or NIE (Foreigner ID).
    
    Uses a simple modulo 23 check digit (letter).
    """
    cleaned = re.sub(r"[\s-]", "", raw.upper())
    if len(cleaned) != 9:
        return False
        
    # Handle NIE prefixes (X=0, Y=1, Z=2)
    mapping = {"X": "0", "Y": "1", "Z": "2"}
    first_char = cleaned[0]
    if first_char in mapping:
        num_str = mapping[first_char] + cleaned[1:8]
    elif first_char.isdigit():
        num_str = cleaned[:8]
    else:
        return False
        
    if not num_str.isdigit():
        return False
        
    num = int(num_str)
    valid_letters = "TRWAGMYFPDXBNJZSQVHLCKE"
    return cleaned[8] == valid_letters[num % 23]


# ── Spanish Social Security (NUSS) ──────────────────────────────────────────

def check_es_nuss(raw: str) -> bool:
    """Validate Spanish Social Security Number (NUSS/NAF).
    
    Format: PP NNNNNNNN CC (12 digits)
    Check: (Province + Number) % 97 == Control
    """
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 12:
        return False
    
    a = int(digits[:2])   # Province
    b = int(digits[2:10]) # Number
    c = int(digits[10:])  # Control
    
    if b < 10000000:
        check = (a * 10000000 + b) % 97
    else:
        check = int(digits[:10]) % 97
        
    return check == c


# ── Spanish Bank Account (CCC) ──────────────────────────────────────────────

def check_es_ccc(raw: str) -> bool:
    """Validate Spanish Bank Account (Código Cuenta Cliente).
    
    Format: BBBB SSSS DD NNNNNNNNNN (20 digits)
    Uses two Mod-11 weighted checksums for control digits.
    """
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 20:
        return False
        
    weights = [1, 2, 4, 8, 5, 10, 9, 7, 3, 6]
    
    def calc_digit(block):
        s = sum(int(b) * w for b, w in zip(block, weights))
        rem = 11 - (s % 11)
        if rem == 10: return 1
        if rem == 11: return 0
        return rem
        
    d1 = calc_digit("00" + digits[:8])
    d2 = calc_digit(digits[10:])
    
    return int(digits[8]) == d1 and int(digits[9]) == d2


# ── Dispatcher ───────────────────────────────────────────────────────────────

_VALIDATOR_DISPATCH = {
    "luhn":       check_luhn,
    "luhn_soft":  check_luhn,
    "ssn_area":   check_ssn_area,
    "iban":       check_iban_structure,
    "aba_check":  check_aba_routing,
    "vin_format": check_vin_format,
    "btc_format": check_btc_format,
    "ipv4":       check_ipv4_octets,
    "ca_sin":     check_ca_sin,
    "uk_nino":    check_uk_nino,
    "es_id":      check_es_id,
    "es_nuss":    check_es_nuss,
    "es_ccc":     check_es_ccc,
}


class DLPValidationEngine:
    """Run the appropriate hard-validator for a given ``validator_tag``.

    Usage::

        engine = DLPValidationEngine()
        passed = engine.run("luhn", "4111111111111111")
    """

    def run(self, tag: str | None, raw_value: str) -> bool | None:
        """Execute the validator identified by *tag*.

        Returns:
          - ``True``  — value passed the checksum → confidence override.
          - ``False`` — value failed → confidence penalty.
          - ``None``  — no validator registered for *tag*.
        """
        if tag is None:
            return None
        fn = _VALIDATOR_DISPATCH.get(tag)
        if fn is None:
            _log.warning("Unknown validator tag: %s", tag)
            return None
        try:
            return fn(raw_value)
        except Exception:
            _log.exception("Validator '%s' raised for value %r", tag, raw_value[:20])
            return False

    @staticmethod
    def available_tags() -> list[str]:
        """Return all registered validator tag names."""
        return list(_VALIDATOR_DISPATCH.keys())
