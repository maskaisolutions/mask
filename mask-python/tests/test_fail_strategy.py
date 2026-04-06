"""Tests for MASK_FAIL_STRATEGY env var behaviour."""

import os
import pytest
from unittest.mock import patch, MagicMock

from mask_privacy.core.exceptions import MaskVaultConnectionError
from mask_privacy.core.vault import encode, RedisVault


class TestFailStrategyClosed:
    """When MASK_FAIL_STRATEGY=closed, vault errors should raise."""

    def test_redis_vault_raises_on_connection_failure(self):
        """RedisVault.__init__ should raise MaskVaultConnectionError when Redis is unreachable."""
        with patch.dict(os.environ, {"MASK_FAIL_STRATEGY": "closed"}):
            with patch("redis.Redis") as mock_redis:
                mock_redis.from_url.return_value.ping.side_effect = Exception("Connection refused")
                with pytest.raises(MaskVaultConnectionError):
                    RedisVault()

    def test_encode_raises_when_closed(self):
        """When fail strategy is closed, encode should raise if vault.store fails."""
        with patch.dict(os.environ, {"MASK_FAIL_STRATEGY": "closed"}):
            mock_vault = MagicMock()
            mock_vault.get_token_by_plaintext_hash.return_value = None
            mock_vault.retrieve.return_value = None
            mock_vault.store.side_effect = MaskVaultConnectionError("Write failed")
            
            with patch("mask_privacy.core.vault.get_vault", return_value=mock_vault):
                with pytest.raises(MaskVaultConnectionError):
                    encode("plaintext")


class TestFailStrategyOpen:
    """When MASK_FAIL_STRATEGY=open (default), encode should be graceful and return plaintext."""

    def test_vault_store_always_raises(self):
        """vault.store should ALWAYS raise on failure, regardless of fail strategy."""
        with patch.dict(os.environ, {"MASK_FAIL_STRATEGY": "open"}):
            with patch("redis.from_url") as mock_from_url:
                mock_db = mock_from_url.return_value
                mock_db.pipeline.return_value.execute.side_effect = Exception("Write failed")
                
                vault = RedisVault()
                with pytest.raises(MaskVaultConnectionError):
                    vault.store("tok123", "cipher", 600, pt_hash="abc123")

    def test_encode_raises_even_when_open(self):
        """encode() now always fail-shuts to prevent PII leakage, regardless of strategy."""
        with patch.dict(os.environ, {"MASK_FAIL_STRATEGY": "open"}):
            mock_vault = MagicMock()
            mock_vault.get_token_by_plaintext_hash.return_value = None
            mock_vault.retrieve.return_value = None
            mock_vault.store.side_effect = MaskVaultConnectionError("Write failed")
            
            with patch("mask_privacy.core.vault.get_vault", return_value=mock_vault):
                with pytest.raises(MaskVaultConnectionError):
                    encode("secret text")


class TestFailStrategyDefault:
    """Default behaviour (no env var) should be 'closed'."""

    def test_default_is_open(self):
        from mask_privacy.core.vault import _get_fail_strategy
        with patch.dict(os.environ, {}, clear=False):
            if "MASK_FAIL_STRATEGY" in os.environ:
                del os.environ["MASK_FAIL_STRATEGY"]
            assert _get_fail_strategy() == "closed"
