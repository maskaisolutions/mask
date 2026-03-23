"""Tests for MASK_FAIL_STRATEGY env var behaviour."""

import os
import pytest
from unittest.mock import patch, MagicMock

from mask_privacy.core.exceptions import MaskVaultConnectionError


class TestFailStrategyClosed:
    """When MASK_FAIL_STRATEGY=closed, vault errors should raise."""

    def test_redis_vault_raises_on_connection_failure(self):
        """RedisVault.__init__ should raise MaskVaultConnectionError when Redis is unreachable."""
        with patch.dict(os.environ, {"MASK_FAIL_STRATEGY": "closed"}):
            from mask_privacy.core.vault import RedisVault
            with patch("redis.Redis") as mock_redis:
                mock_redis.from_url.return_value.ping.side_effect = Exception("Connection refused")
                with pytest.raises(MaskVaultConnectionError):
                    RedisVault()

    def test_dynamodb_atomic_write_raises_when_closed(self):
        """DynamoDB transact_write_items failure should raise."""
        with patch.dict(os.environ, {"MASK_FAIL_STRATEGY": "closed"}):
            from mask_privacy.core.vault import DynamoDBVault
            with patch("boto3.resource") as mock_resource:
                mock_db = MagicMock()
                mock_resource.return_value = mock_db
                # The client is usually self._dynamodb.meta.client
                mock_db.meta.client.transact_write_items.side_effect = Exception("Transaction failed")
                
                vault = DynamoDBVault()
                with pytest.raises(MaskVaultConnectionError):
                    vault.store("tok123", "cipher", 600, pt_hash="abc123")


class TestFailStrategyOpen:
    """When MASK_FAIL_STRATEGY=open (default), vault errors should be graceful, except for DynamoDB."""

    def test_dynamodb_atomic_write_raises_even_when_open(self):
        """DynamoDB transact_write_items failure should ALWAYS raise to prevent data loss."""
        with patch.dict(os.environ, {"MASK_FAIL_STRATEGY": "open"}):
            from mask_privacy.core.vault import DynamoDBVault
            with patch("boto3.resource") as mock_resource:
                mock_db = MagicMock()
                mock_resource.return_value = mock_db
                mock_db.meta.client.transact_write_items.side_effect = Exception("Transaction failed")
                
                vault = DynamoDBVault()
                with pytest.raises(MaskVaultConnectionError):
                    vault.store("tok123", "cipher", 600, pt_hash="abc123")

    def test_redis_store_graceful_when_open(self):
        """Redis store failure should NOT raise when open."""
        with patch.dict(os.environ, {"MASK_FAIL_STRATEGY": "open"}):
            from mask_privacy.core.vault import RedisVault
            with patch("redis.from_url") as mock_from_url:
                mock_db = mock_from_url.return_value
                mock_db.pipeline.return_value.execute.side_effect = Exception("Write failed")
                
                vault = RedisVault()
                # Should NOT raise
                vault.store("tok123", "cipher", 600, pt_hash="abc123")


class TestFailStrategyDefault:
    """Default behaviour (no env var) should be 'open'."""

    def test_default_is_open(self):
        from mask_privacy.core.vault import _get_fail_strategy
        with patch.dict(os.environ, {}, clear=False):
            if "MASK_FAIL_STRATEGY" in os.environ:
                del os.environ["MASK_FAIL_STRATEGY"]
            assert _get_fail_strategy() == "open"
