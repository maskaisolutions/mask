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
    from mask_privacy.core.key_provider import set_key_provider, AwsKmsKeyProvider
    set_key_provider(AwsKmsKeyProvider(key_id="alias/mask-key"))
"""

import logging
import threading
from abc import ABC, abstractmethod
from typing import Optional
from mask_privacy import config

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

    def get_keyring(self) -> Optional[str]:
        """Return a JSON keyring string (e.g. from KMS / Secrets Manager).

        This method is optional for providers that do not manage the keyring.
        Return None to fall back to the MASK_KEYRING environment variable.
        Override in KMS-backed providers to supply the keyring from a
        secure external source, removing the need for MASK_KEYRING in env.
        """
        return None


class EnvKeyProvider(BaseKeyProvider):
    """Default provider: reads keys from environment variables.

    This preserves backwards compatibility with existing deployments.
    """

    def get_encryption_key(self) -> Optional[str]:
        key = config.MASK_ENCRYPTION_KEY
        if not key and config.MASK_STRICT_PROD:
            raise RuntimeError(
                "MASK_STRICT_PROD is enabled but MASK_ENCRYPTION_KEY is not set. "
                "The SDK is configured to Fail-Shut when keys are missing in production environments."
            )
        return key

    def get_master_key(self) -> Optional[str]:
        return config.MASK_MASTER_KEY or None

    def get_keyring(self) -> Optional[str]:
        """Return MASK_KEYRING from environment (default behaviour)."""
        return config.MASK_KEYRING or None


# Stub providers for enterprise key management services

class AwsKmsKeyProvider(BaseKeyProvider):
    """AWS KMS-backed key provider.
    
    Supports two modes:
    1. **Envelope Encryption (Recommended)**: Decrypts a base64-encoded encrypted 
       data key (EDK) from ``MASK_ENCRYPTED_KEY.``
    2. **Secret-as-Key (Fallback)**: Retrieves a raw key from Secrets Manager 
       using the ``key_id`` as the SecretId.
    """

    def __init__(self, key_id: str, region: str = "us-east-1") -> None:
        self.key_id = key_id
        self.region = region
        self._kms = None
        self._sm = None

    def _get_kms(self):
        if self._kms is None:
            import boto3
            self._kms = boto3.client("kms", region_name=self.region)
        return self._kms

    def _get_sm(self):
        if self._sm is None:
            import boto3
            self._sm = boto3.client("secretsmanager", region_name=self.region)
        return self._sm

    def get_encryption_key(self) -> Optional[str]:
        # Mode 1: Envelope Encryption (EDK in environment)
        edk_b64 = config.MASK_ENCRYPTED_KEY
        if edk_b64:
            try:
                import base64
                ciphertext = base64.b64decode(edk_b64)
                resp = self._get_kms().decrypt(
                    CiphertextBlob=ciphertext,
                    KeyId=self.key_id
                )
                plaintext = resp["Plaintext"]
                # Fernet keys are base64-encoded 32 bytes
                return base64.urlsafe_b64encode(plaintext).decode("utf-8")
            except Exception as e:
                logger.error("AWS KMS envelope decryption failed: %s", e)
                raise

        # Fail-Shut enforcement: envelope encryption is required if strict mode is enabled or not dev mode
        if config.MASK_STRICT_PROD or not config.MASK_DEV_MODE:
            raise RuntimeError(
                "MASK_ENCRYPTED_KEY is not set. "
                "Envelope encryption via KMS is required in production environments. "
                "Set MASK_ENCRYPTED_KEY to a KMS-encrypted data encryption key."
            )

        # Mode 2: Secret-as-Key fallback (dev mode only)
        try:
            val = self._get_sm().get_secret_value(SecretId=self.key_id)
            return val.get("SecretString")
        except Exception as e:
            logger.error("AWS Secrets Manager retrieval failed: %s", e)
            raise

    def get_master_key(self) -> Optional[str]:
        return self.get_encryption_key()

    def get_keyring(self) -> Optional[str]:
        """Retrieve the JSON keyring from AWS Secrets Manager.

        If ``MASK_KEYRING_SECRET_ID`` is set, this provider fetches the full
        JSON keyring document (e.g. ``{"v1": "key...", "v2": "newkey"}``) from
        Secrets Manager, allowing zero-downtime key rotation without ever
        writing key material to environment variables.
        """
        secret_id = config.MASK_KEYRING_SECRET_ID if hasattr(config, 'MASK_KEYRING_SECRET_ID') else None
        if not secret_id:
            # Fallback: let CryptoEngine read from MASK_KEYRING env var
            return None
        try:
            val = self._get_sm().get_secret_value(SecretId=secret_id)
            keyring_str = val.get("SecretString")
            if not keyring_str:
                raise RuntimeError("MASK_KEYRING_SECRET_ID returned an empty secret.")
            logger.info("Keyring loaded from AWS Secrets Manager (secret: %s)", secret_id)
            return keyring_str
        except Exception as e:
            logger.error("Failed to retrieve keyring from AWS Secrets Manager: %s", e)
            raise


class AzureKeyVaultProvider(BaseKeyProvider):
    """Azure Key Vault-backed key provider."""

    def __init__(self, vault_url: str, secret_name: str = "mask-encryption-key") -> None:
        self.vault_url = vault_url
        self.secret_name = secret_name
        self._client = None

    def _get_client(self):
        if self._client is None:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential
            self._client = SecretClient(vault_url=self.vault_url, credential=DefaultAzureCredential())
        return self._client

    def get_encryption_key(self) -> Optional[str]:
        try:
            secret = self._get_client().get_secret(self.secret_name)
            return secret.value
        except Exception as e:
            logger.error("Azure Key Vault retrieval failed: %s", e)
            raise

    def get_master_key(self) -> Optional[str]:
        return self.get_encryption_key()

    def get_keyring(self) -> Optional[str]:
        """Retrieve the JSON keyring from Azure Key Vault.

        If a secret named ``mask-keyring`` (or ``<secret_name>-keyring``) exists
        in the vault, it is used as the full JSON keyring document.
        """
        keyring_secret = self.secret_name + "-keyring"
        try:
            secret = self._get_client().get_secret(keyring_secret)
            if secret.value:
                logger.info("Keyring loaded from Azure Key Vault (secret: %s)", keyring_secret)
                return secret.value
        except Exception:
            pass  # Secret may not exist; fall back to env
        return None


class HashiCorpVaultProvider(BaseKeyProvider):
    """HashiCorp Vault-backed key provider."""

    def __init__(self, vault_addr: str, secret_path: str = "secret/data/mask", token: Optional[str] = None) -> None:
        self.vault_addr = vault_addr
        self.secret_path = secret_path
        self.token = token or config.VAULT_TOKEN
        self._client = None

    def _get_client(self):
        if self._client is None:
            import hvac
            self._client = hvac.Client(url=self.vault_addr, token=self.token)
        return self._client

    def get_encryption_key(self) -> Optional[str]:
        try:
            read_response = self._get_client().read(self.secret_path)
            # Assuming standard kv-v2 structure
            data = read_response.get("data", {}).get("data", {})
            return data.get("encryption_key") or data.get("value")
        except Exception as e:
            logger.error("HashiCorp Vault retrieval failed: %s", e)
            raise

    def get_master_key(self) -> Optional[str]:
        return self.get_encryption_key()

    def get_keyring(self) -> Optional[str]:
        """Retrieve the JSON keyring from HashiCorp Vault.

        Looks for a ``keyring`` key in the secret at ``secret_path``.
        """
        try:
            read_response = self._get_client().read(self.secret_path)
            data = read_response.get("data", {}).get("data", {})
            keyring_str = data.get("keyring")
            if keyring_str:
                logger.info("Keyring loaded from HashiCorp Vault (path: %s)", self.secret_path)
                return keyring_str
        except Exception as e:
            logger.error("HashiCorp Vault keyring retrieval failed: %s", e)
        return None


# Singleton accessor

_provider_lock = threading.Lock()
_provider_instance: Optional[BaseKeyProvider] = None


def get_key_provider() -> BaseKeyProvider:
    """Return the active key provider singleton (lazy-init, thread-safe).

    Defaults to ``EnvKeyProvider`` if no custom provider has been set.
    """
    global _provider_instance
    if _provider_instance is None:
        with _provider_lock:
            if _provider_instance is None:
                _provider_instance = EnvKeyProvider()
                logger.info("Using default EnvKeyProvider for key management.")
    return _provider_instance


def set_key_provider(provider: BaseKeyProvider) -> None:
    """Replace the active key provider singleton.

    Call this early in application startup, before any encode/decode
    operations, to inject a custom key source::

        from mask_privacy.core.key_provider import set_key_provider, AwsKmsKeyProvider
        set_key_provider(AwsKmsKeyProvider(key_id="alias/mask"))
    """
    global _provider_instance
    _provider_instance = provider
    logger.info("Key provider set to %s", type(provider).__name__)


def reset_key_provider() -> None:
    """Clear the singleton.  Useful in tests."""
    global _provider_instance
    _provider_instance = None

