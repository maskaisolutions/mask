"""Tests for the pluggable KeyProvider abstraction."""

import os
import pytest

from mask.core.key_provider import (
    EnvKeyProvider,
    AwsKmsKeyProvider,
    AzureKeyVaultProvider,
    HashiCorpVaultProvider,
    get_key_provider,
    set_key_provider,
    reset_key_provider,
)


@pytest.fixture(autouse=True)
def _clean_providers():
    reset_key_provider()
    yield
    reset_key_provider()


def test_default_is_env_provider():
    provider = get_key_provider()
    assert isinstance(provider, EnvKeyProvider)


def test_set_custom_provider():
    class DummyProvider(EnvKeyProvider):
        pass
        
    set_key_provider(DummyProvider())
    assert isinstance(get_key_provider(), DummyProvider)


def test_env_provider_reads_from_environ(monkeypatch):
    monkeypatch.setenv("MASK_ENCRYPTION_KEY", "test-enc-key")
    monkeypatch.setenv("MASK_MASTER_KEY", "test-master-key")
    
    provider = EnvKeyProvider()
    assert provider.get_encryption_key() == "test-enc-key"
    assert provider.get_master_key() == "test-master-key"


def test_env_provider_falls_back_master_to_encryption(monkeypatch):
    monkeypatch.setenv("MASK_ENCRYPTION_KEY", "fallback-key")
    monkeypatch.delenv("MASK_MASTER_KEY", raising=False)
    
    provider = EnvKeyProvider()
    assert provider.get_encryption_key() == "fallback-key"
    assert provider.get_master_key() == "fallback-key"


def test_stub_providers_raise_not_implemented():
    aws = AwsKmsKeyProvider("alias/key")
    with pytest.raises(NotImplementedError):
        aws.get_encryption_key()
        
    azure = AzureKeyVaultProvider("https://vault")
    with pytest.raises(NotImplementedError):
        azure.get_master_key()
        
    hashi = HashiCorpVaultProvider("https://vault:8200")
    with pytest.raises(NotImplementedError):
        hashi.get_encryption_key()
