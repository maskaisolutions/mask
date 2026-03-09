"""
Mask Privacy SDK
Just-In-Time Privacy Middleware for AI Agents.

Provides format-preserving encryption, local/distributed vaulting,
and framework-agnostic tool interception hooks.
"""

__version__ = "0.1.0"

from mask.core.vault import get_vault, encode, decode
from mask.core.fpe import generate_fpe_token

__all__ = [
    "get_vault",
    "encode",
    "decode",
    "generate_fpe_token",
]
