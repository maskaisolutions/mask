"""
Format-Preserving Encryption (FPE) token generation.

Generates structurally valid tokens that preserve the *format* of the
original data type so downstream tools, schemas, and validators continue
to work without modification.

Supported formats:
  - Email  →  tkn-<hex>@email.com
  - Phone  →  +1-555-<7 digits>
  - SSN    →  000-00-<4 digits>
  - Default → [TKN-<hex>]
"""

import secrets
import string
import re


# ---------------------------------------------------------------------------
# Detectors — order matters: first match wins
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}$")
_SSN_RE   = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_CC_RE    = re.compile(r"^(?:\d{4}[ \-]?){3}\d{4}$")
_ROUTING_RE = re.compile(r"^\d{9}$")


def _random_hex(n: int = 8) -> str:
    """Return *n* random hex characters."""
    return "".join(secrets.choice(string.hexdigits).lower() for _ in range(n))


def _random_digits(n: int) -> str:
    """Return *n* random decimal digits (using cryptographically secure entropy)."""
    return "".join(secrets.choice(string.digits) for _ in range(n))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_fpe_token(raw_text: str) -> str:
    """Return a format-preserving token for *raw_text*.

    The token is structurally compatible with the original data type
    so that downstream schema validators, regex checks, and database
    constraints continue to pass.
    """
    text = raw_text.strip()

    if _EMAIL_RE.match(text):
        return f"tkn-{_random_hex()}@email.com"

    if _PHONE_RE.match(text):
        return f"+1-555-{_random_digits(7)}"

    if _SSN_RE.match(text):
        return f"000-00-{_random_digits(4)}"

    # Standard 16-digit credit card (format: 4000-0000-0000-XXXX)
    if _CC_RE.match(text):
        return f"4000-0000-0000-{_random_digits(4)}"

    # US ABA Routing Number (format: 000000XXX)
    if _ROUTING_RE.match(text):
        return f"000000{_random_digits(3)}"

    # Opaque fallback
    return f"[TKN-{_random_hex()}]"


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
    
    # Email tokens: tkn-<hex>@email.com
    if v.startswith("tkn-") and v.endswith("@email.com"):
        return True
    
    # Phone tokens: +1-555-XXXXXXX  (555 is the standard fictional exchange)
    if v.startswith("+1-555-") and len(v) == 14:
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
    
    # Opaque fallback tokens: [TKN-<hex>]
    if v.startswith("[TKN-") and v.endswith("]"):
        return True
    
    return False
