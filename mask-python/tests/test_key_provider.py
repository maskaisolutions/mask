"""Tests for the pluggable KeyProvider abstraction."""

import os
import sys
import pytest

from mask_privacy.core.key_provider import (
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


def test_kms_providers_functional(monkeypatch, mocker):
    # Mock AWS SecretsManager
    mock_sm = mocker.Mock()
    mock_sm.get_secret_value.return_value = {"SecretString": "aws-key"}
    mocker.patch("boto3.client", return_value=mock_sm)
    
    aws = AwsKmsKeyProvider("alias/key")
    assert aws.get_encryption_key() == "aws-key"
    
    # Mock Azure Key Vault (mock sys.modules since azure may not be installed)
    mock_azure_module = mocker.Mock()
    mock_identity_module = mocker.Mock()
    mocker.patch.dict(sys.modules, {
        "azure": mock_azure_module,
        "azure.keyvault": mock_azure_module,
        "azure.keyvault.secrets": mock_azure_module,
        "azure.identity": mock_identity_module
    })
    
    mock_client_inst = mocker.Mock()
    mock_client_inst.get_secret.return_value = mocker.Mock(value="azure-key")
    mock_azure_module.SecretClient.return_value = mock_client_inst
    
    azure = AzureKeyVaultProvider("https://vault")
    assert azure.get_encryption_key() == "azure-key"
    
    # Mock HashiCorp Vault
    mock_hvac_module = mocker.Mock()
    mocker.patch.dict(sys.modules, {"hvac": mock_hvac_module})
    
    mock_hvac_inst = mocker.Mock()
    mock_hvac_inst.read.return_value = {"data": {"data": {"value": "hashi-key"}}}
    mock_hvac_module.Client.return_value = mock_hvac_inst
    
    hashi = HashiCorpVaultProvider("https://vault:8200")
    assert hashi.get_encryption_key() == "hashi-key"
