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

logger = logging.getLogger("mask.fpe")


# ---------------------------------------------------------------------------
# Master key management
# ---------------------------------------------------------------------------

_master_key: Optional[bytes] = None


def _get_master_key() -> bytes:
    """Return the HMAC master key, lazily initialised from the environment."""
    global _master_key
    if _master_key is None:
        raw = os.environ.get("MASK_MASTER_KEY", "")
        if not raw:
            # Fall back to the Fernet encryption key for convenience
            raw = os.environ.get("MASK_ENCRYPTION_KEY", "")
        if not raw:
            # Auto-generate a session-local key (non-persistent)
            import secrets
            raw = secrets.token_hex(32)
            os.environ["MASK_MASTER_KEY"] = raw
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

def generate_fpe_token(raw_text: str) -> str:
    """Return a **deterministic**, format-preserving token for *raw_text*.

    The token is structurally compatible with the original data type
    so that downstream schema validators, regex checks, and database
    constraints continue to pass.

    Determinism guarantee: the same *raw_text* with the same MASK_MASTER_KEY
    will always produce the same token.
    """
    text = raw_text.strip()

    if _EMAIL_RE.match(text):
        return f"tkn-{_hmac_hex(text)}@email.com"

    if _PHONE_RE.match(text):
        return f"+1-555-{_hmac_digits(text, 7)}"

    if _SSN_RE.match(text):
        return f"000-00-{_hmac_digits(text, 4)}"

    # Standard 16-digit credit card (format: 4000-0000-0000-XXXX)
    if _CC_RE.match(text):
        return f"4000-0000-0000-{_hmac_digits(text, 4)}"

    # US ABA Routing Number (format: 000000XXX)
    if _ROUTING_RE.match(text):
        return f"000000{_hmac_digits(text, 3)}"

    # Opaque fallback
    return f"[TKN-{_hmac_hex(text)}]"


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
