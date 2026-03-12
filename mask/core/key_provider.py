"""
Pluggable Key Provider abstraction for Mask SDK.

Instead of hard-coded ``os.environ,`` it reads with a pluggable interface so
enterprises can supply encryption keys from AWS KMS, Azure Key Vault,
HashiCorp Vault, or any custom source without exposing secrets in
environment variables.

Usage::

    # Default: reads from env vars (backwards compatible)
    provider = get_key_provider()

    # Custom: inject your own provider
    from mask.core.key_provider import set_key_provider, AwsKmsKeyProvider
    set_key_provider(AwsKmsKeyProvider(key_id="alias/mask-key"))
"""

import os
import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger("mask.key_provider")


class BaseKeyProvider(ABC):
    """Interface that all key providers must implement.

    A key provider supplies two secrets:

    - **encryption_key**: Used by ``CryptoEngine`` (Fernet) to encrypt
      plaintext payloads before they enter the vault.
    - **master_key**: Used by ``generate_fpe_token`` (HMAC-SHA256) to
      derive deterministic, format-preserving tokens.
    """

    @abstractmethod
    def get_encryption_key(self) -> Optional[str]:
        """Return the Fernet encryption key, or None to auto-generate."""

    @abstractmethod
    def get_master_key(self) -> Optional[str]:
        """Return the HMAC master key, or None to auto-generate."""


class EnvKeyProvider(BaseKeyProvider):
    """Default provider: reads keys from environment variables.

    This preserves backwards compatibility with existing deployments.
    """

    def get_encryption_key(self) -> Optional[str]:
        return os.environ.get("MASK_ENCRYPTION_KEY")

    def get_master_key(self) -> Optional[str]:
        key = os.environ.get("MASK_MASTER_KEY", "")
        if not key:
            key = os.environ.get("MASK_ENCRYPTION_KEY", "")
        return key or None


# Stub providers for enterprise key management services

class AwsKmsKeyProvider(BaseKeyProvider):
    """AWS KMS-backed key provider (stub — implement with boto3).

    Usage::

        from mask.core.key_provider import set_key_provider, AwsKmsKeyProvider
        set_key_provider(AwsKmsKeyProvider(
            key_id="alias/mask-encryption-key",
            region="us-east-1",
        ))

    Requires ``boto3`` and valid AWS credentials.
    """

    def __init__(self, key_id: str, region: str = "us-east-1") -> None:
        self.key_id = key_id
        self.region = region

    def get_encryption_key(self) -> Optional[str]:
        raise NotImplementedError(
            "AwsKmsKeyProvider.get_encryption_key() is a stub. "
            "Implement with boto3 KMS GenerateDataKey / Decrypt to "
            "retrieve the Fernet key from AWS KMS."
        )

    def get_master_key(self) -> Optional[str]:
        raise NotImplementedError(
            "AwsKmsKeyProvider.get_master_key() is a stub. "
            "Implement with boto3 KMS to retrieve the HMAC master key."
        )


class AzureKeyVaultProvider(BaseKeyProvider):
    """Azure Key Vault-backed key provider (stub — implement with azure-keyvault-secrets).

    Usage::

        from mask.core.key_provider import set_key_provider, AzureKeyVaultProvider
        set_key_provider(AzureKeyVaultProvider(
            vault_url="https://my-vault.vault.azure.net",
        ))
    """

    def __init__(self, vault_url: str) -> None:
        self.vault_url = vault_url

    def get_encryption_key(self) -> Optional[str]:
        raise NotImplementedError(
            "AzureKeyVaultProvider.get_encryption_key() is a stub. "
            "Implement with azure-keyvault-secrets SecretClient."
        )

    def get_master_key(self) -> Optional[str]:
        raise NotImplementedError(
            "AzureKeyVaultProvider.get_master_key() is a stub. "
            "Implement with azure-keyvault-secrets SecretClient."
        )


class HashiCorpVaultProvider(BaseKeyProvider):
    """HashiCorp Vault-backed key provider (stub — implement with hvac).

    Usage::

        from mask.core.key_provider import set_key_provider, HashiCorpVaultProvider
        set_key_provider(HashiCorpVaultProvider(
            vault_addr="https://vault.example.com:8200",
            secret_path="secret/data/mask",
        ))
    """

    def __init__(self, vault_addr: str, secret_path: str = "secret/data/mask") -> None:
        self.vault_addr = vault_addr
        self.secret_path = secret_path

    def get_encryption_key(self) -> Optional[str]:
        raise NotImplementedError(
            "HashiCorpVaultProvider.get_encryption_key() is a stub. "
            "Implement with the `hvac` Python client."
        )

    def get_master_key(self) -> Optional[str]:
        raise NotImplementedError(
            "HashiCorpVaultProvider.get_master_key() is a stub. "
            "Implement with the `hvac` Python client."
        )


# Singleton accessor

_provider_instance: Optional[BaseKeyProvider] = None


def get_key_provider() -> BaseKeyProvider:
    """Return the active key provider singleton.

    Defaults to ``EnvKeyProvider`` if no custom provider has been set.
    """
    global _provider_instance
    if _provider_instance is None:
        _provider_instance = EnvKeyProvider()
        logger.info("Using default EnvKeyProvider for key management.")
    return _provider_instance


def set_key_provider(provider: BaseKeyProvider) -> None:
    """Replace the active key provider singleton.

    Call this early in application startup, before any encode/decode
    operations, to inject a custom key source::

        from mask.core.key_provider import set_key_provider, AwsKmsKeyProvider
        set_key_provider(AwsKmsKeyProvider(key_id="alias/mask"))
    """
    global _provider_instance
    _provider_instance = provider
    logger.info("Key provider set to %s", type(provider).__name__)


def reset_key_provider() -> None:
    """Clear the singleton.  Useful in tests."""
    global _provider_instance
    _provider_instance = None

