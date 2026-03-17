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
            with pytest.raises(MaskVaultConnectionError):
                from mask_privacy.core.vault import RedisVault
                # Point at a port that is definitely not running Redis
                with patch.dict(os.environ, {"MASK_REDIS_URL": "redis://localhost:59999/0"}):
                    RedisVault()

    def test_dynamodb_atomic_write_raises_when_closed(self):
        """DynamoDB transact_write_items failure should raise when strategy is closed."""
        with patch.dict(os.environ, {"MASK_FAIL_STRATEGY": "closed"}):
            from mask_privacy.core.vault import DynamoDBVault

            # Create a mock DynamoDB vault
            with patch("boto3.resource") as mock_resource, \
                 patch("boto3.client") as mock_client:
                mock_table = MagicMock()
                mock_resource.return_value.Table.return_value = mock_table

                vault = DynamoDBVault.__new__(DynamoDBVault)
                vault._table_name = "test-table"
                vault._table = mock_table
                vault._client = mock_resource.return_value

                # Simulate transact_write_items failure
                mock_ddb_client = MagicMock()
                mock_ddb_client.transact_write_items.side_effect = Exception("Transaction cancelled")
                mock_client.return_value = mock_ddb_client

                with pytest.raises(MaskVaultConnectionError):
                    vault.store("tok123", "cipher", 600, pt_hash="abc123")


class TestFailStrategyOpen:
    """When MASK_FAIL_STRATEGY=open (default), vault errors should be graceful."""

    def test_dynamodb_atomic_write_falls_back_when_open(self):
        """DynamoDB transact_write_items failure should fall back to put_item when open."""
        with patch.dict(os.environ, {"MASK_FAIL_STRATEGY": "open"}):
            from mask_privacy.core.vault import DynamoDBVault

            with patch("boto3.resource") as mock_resource, \
                 patch("boto3.client") as mock_client:
                mock_table = MagicMock()
                mock_resource.return_value.Table.return_value = mock_table

                vault = DynamoDBVault.__new__(DynamoDBVault)
                vault._table_name = "test-table"
                vault._table = mock_table
                vault._client = mock_resource.return_value

                mock_ddb_client = MagicMock()
                mock_ddb_client.transact_write_items.side_effect = Exception("Transaction cancelled")
                mock_client.return_value = mock_ddb_client

                # Should NOT raise — falls back to non-atomic put_item
                vault.store("tok123", "cipher", 600, pt_hash="abc123")

                # Verify put_item was called as fallback
                assert mock_table.put_item.call_count == 2  # forward + reverse


class TestFailStrategyDefault:
    """Default behaviour (no env var) should be 'open'."""

    def test_default_is_open(self):
        from mask_privacy.core.vault import _get_fail_strategy
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MASK_FAIL_STRATEGY", None)
            assert _get_fail_strategy() == "open"
