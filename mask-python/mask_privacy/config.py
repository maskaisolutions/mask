"""
Mask Privacy SDK Configuration.
Centralizes all environment-based settings with detailed documentation.
"""

import os
from typing import List, Optional

def get_env_bool(name: str, default: bool = False) -> bool:
    """Helper to parse boolean environment variables."""
    return os.environ.get(name, str(default)).lower() in ("true", "1", "yes")

def get_env_int(name: str, default: int) -> int:
    """Helper to parse integer environment variables."""
    try:
        return int(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default

def get_env_float(name: str, default: float) -> float:
    """Helper to parse float environment variables."""
    try:
        return float(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default

# --- DYNAMIC CONFIGURATION ACCESS ---

def __getattr__(name: str):
    """Allow dynamic access to environment variables so that tests can use monkeypatch."""
    
    # General
    if name == "MASK_ENV":
        return os.environ.get("MASK_ENV", "production").lower()
    if name == "MASK_DEV_MODE":
        return get_env_bool("MASK_DEV_MODE", False)
    if name == "MASK_LOG_LEVEL":
        return os.environ.get("MASK_LOG_LEVEL", "info").lower()
    
    # Security
    if name == "MASK_ENCRYPTION_KEY":
        return os.environ.get("MASK_ENCRYPTION_KEY")
    if name == "MASK_MASTER_KEY":
        return os.environ.get("MASK_MASTER_KEY", os.environ.get("MASK_ENCRYPTION_KEY", ""))
    if name == "MASK_ENCRYPTED_KEY":
        return os.environ.get("MASK_ENCRYPTED_KEY")
    if name == "MASK_STRICT_PROD":
        return get_env_bool("MASK_STRICT_PROD", False)
    if name == "MASK_BLIND_INDEX_SALT":
        return os.environ.get("MASK_BLIND_INDEX_SALT", "mask-blind-index")
    if name == "VAULT_TOKEN":
        return os.environ.get("VAULT_TOKEN")
    
    # Vault
    if name == "MASK_VAULT_TYPE":
        return os.environ.get("MASK_VAULT_TYPE", "memory").lower()
    if name == "MASK_FAIL_STRATEGY":
        return os.environ.get("MASK_FAIL_STRATEGY", "").lower()
    if name == "MASK_VAULT_TTL":
        return get_env_int("MASK_VAULT_TTL", 600)
    if name == "MASK_VAULT_CLEANUP_FREQUENCY":
        return get_env_float("MASK_VAULT_CLEANUP_FREQUENCY", 0.01)
    
    # Backend Connections
    if name == "MASK_REDIS_URL":
        return os.environ.get("MASK_REDIS_URL", "redis://localhost:6379/0")
    if name == "MASK_DYNAMODB_REGION":
        return os.environ.get("MASK_DYNAMODB_REGION", "us-east-1")
    if name == "MASK_DYNAMODB_TABLE":
        return os.environ.get("MASK_DYNAMODB_TABLE", "mask-vault")
    if name == "MASK_DYNAMODB_MAX_SOCKETS":
        return get_env_int("MASK_DYNAMODB_MAX_SOCKETS", 50)
    if name == "MASK_MEMCACHED_HOST":
        return os.environ.get("MASK_MEMCACHED_HOST", "localhost")
    if name == "MASK_MEMCACHED_PORT":
        return get_env_int("MASK_MEMCACHED_PORT", 11211)
    
    # NLP & Detection
    if name == "MASK_LANGUAGES":
        return os.environ.get("MASK_LANGUAGES", "en")
    if name == "MASK_NLP_ENGINE":
        return os.environ.get("MASK_NLP_ENGINE", "spacy").lower()
    if name == "MASK_NLP_MODEL":
        return os.environ.get("MASK_NLP_MODEL")
    if name == "MASK_NLP_MAX_WORKERS":
        return get_env_int("MASK_NLP_MAX_WORKERS", 4)
    if name == "MASK_NLP_TIMEOUT_SECONDS":
        return get_env_float("MASK_NLP_TIMEOUT_SECONDS", 60.0)
    if name == "MASK_SCANNER_TYPE":
        return os.environ.get("MASK_SCANNER_TYPE", "local").lower()
    if name == "MASK_SCANNER_URL":
        return os.environ.get("MASK_SCANNER_URL", "http://localhost:5001/analyze")
    if name == "MASK_MODEL_CACHE_DIR":
        return os.environ.get("MASK_MODEL_CACHE_DIR", os.path.expanduser("~/.cache/mask"))
    
    # Telemetry
    if name == "MASK_AUDIT_LOG_STRICT":
        return get_env_bool("MASK_AUDIT_LOG_STRICT", False)
    if name == "MASK_AUDIT_MAX_BUFFER_SIZE":
        return get_env_int("MASK_AUDIT_MAX_BUFFER_SIZE", 5000)
    
    raise AttributeError(f"module {__name__} has no attribute {name}")

# Redefine constants as placeholders for static analyzers (optional but good for IDEs)
# Note: they will be shadowed by __getattr__ for actual runtime access in 3.7+
MASK_ENV: str
MASK_DEV_MODE: bool
MASK_ENCRYPTION_KEY: Optional[str]
MASK_MASTER_KEY: str
MASK_ENCRYPTED_KEY: Optional[str]
MASK_STRICT_PROD: bool
MASK_BLIND_INDEX_SALT: str
MASK_VAULT_TYPE: str
MASK_FAIL_STRATEGY: str
MASK_VAULT_TTL: int
MASK_VAULT_CLEANUP_FREQUENCY: float
MASK_REDIS_URL: str
MASK_DYNAMODB_REGION: str
MASK_DYNAMODB_TABLE: str
MASK_DYNAMODB_MAX_SOCKETS: int
MASK_MEMCACHED_HOST: str
MASK_MEMCACHED_PORT: int
MASK_LANGUAGES: str
MASK_NLP_ENGINE: str
MASK_NLP_MODEL: Optional[str]
MASK_NLP_MAX_WORKERS: int
MASK_NLP_TIMEOUT_SECONDS: float
MASK_SCANNER_TYPE: str
MASK_SCANNER_URL: str
MASK_MODEL_CACHE_DIR: str
MASK_AUDIT_LOG_STRICT: bool
MASK_AUDIT_MAX_BUFFER_SIZE: int
