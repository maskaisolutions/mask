"""Unit tests for the distributed Vault backends."""

import os
import time
from unittest import mock

import pytest

from mask_privacy.core.vault import DynamoDBVault, MemcachedVault

# DynamoDB Tests

@mock.patch.dict(os.environ, {"MASK_DYNAMODB_TABLE": "test-table", "MASK_DYNAMODB_REGION": "eu-west-1"})
@mock.patch("boto3.resource")
class TestDynamoDBVault:
    
    def test_init_connects_to_boto3(self, mock_resource_method):
        mock_resource = mock.MagicMock()
        mock_resource_method.return_value = mock_resource
        
        vault = DynamoDBVault()
        
        mock_resource_method.assert_called_once_with("dynamodb", region_name="eu-west-1")
        mock_resource.Table.assert_called_once_with("test-table")

    @mock.patch("time.time", return_value=1000)
    def test_store_puts_item_with_ttl(self, mock_time, mock_resource_method):
        mock_table = mock.MagicMock()
        mock_resource_method.return_value.Table.return_value = mock_table
        
        vault = DynamoDBVault()
        from mask_privacy.core.vault import _hash_plaintext
        secret_hash = _hash_plaintext("secret")
        vault.store("tok_1", "enc_secret", ttl_seconds=60, pt_hash=secret_hash)
        
        # Verify transact_write_items was called
        mock_client = mock_resource_method.return_value.meta.client
        mock_client.transact_write_items.assert_called_once()
        args = mock_client.transact_write_items.call_args[1]["TransactItems"]
        
        # Check primary entry
        assert args[0]["Put"]["Item"]["token"]["S"] == "mask:tenant-a:tok_1"
        assert args[0]["Put"]["Item"]["ciphertext"]["S"] == "enc_secret"
        assert args[0]["Put"]["Item"]["ttl"]["N"] == "1060"
        
        # Check reverse entry
        assert args[1]["Put"]["Item"]["token"]["S"] == f"mask-rev:tenant-a:{secret_hash}"
        assert args[1]["Put"]["Item"]["ciphertext"]["S"] == "tok_1"
        assert args[1]["Put"]["Item"]["ttl"]["N"] == "1060"

    @mock.patch("time.time", return_value=1000)
    def test_retrieve_returns_val_and_handles_expiry(self, mock_time, mock_resource_method):
        mock_table = mock.MagicMock()
        mock_resource_method.return_value.Table.return_value = mock_table
        
        # Valid item
        mock_table.get_item.return_value = {
            "Item": {"token": "mask:tenant-a:tok_2", "ciphertext": "safe", "ttl": 1500}
        }
        
        vault = DynamoDBVault()
        assert vault.retrieve("tok_2") == "safe"
        
        # Expired item — include ptr_hash so cleanup can find the reverse mapping
        from mask_privacy.core.vault import _hash_plaintext
        stale_hash = _hash_plaintext("stale")
        mock_table.get_item.return_value = {
            "Item": {"token": "mask:tenant-a:tok_expiration", "ciphertext": "stale", "ttl": 900, "ptr_hash": stale_hash}
        }
        assert vault.retrieve("tok_expiration") is None
        # Should have auto-deleted the expired row and its reverse mapping
        mock_table.delete_item.assert_any_call(Key={"token": f"mask-rev:tenant-a:{stale_hash}"})
        mock_table.delete_item.assert_any_call(Key={"token": "mask:tenant-a:tok_expiration"})

    def test_delete_removes_item(self, mock_resource_method):
        mock_table = mock.MagicMock()
        mock_resource_method.return_value.Table.return_value = mock_table
        
        from mask_privacy.core.vault import _hash_plaintext
        data3_hash = _hash_plaintext("data3")
        
        # Mock get_item so delete() can find the item and its ptr_hash
        def mock_get(Key):
            if Key["token"] == "mask:tenant-a:tok_3":
                return {"Item": {"token": "mask:tenant-a:tok_3", "ciphertext": "data3", "ttl": 9999999999, "ptr_hash": data3_hash}}
            return {}
        mock_table.get_item.side_effect = mock_get
        
        vault = DynamoDBVault()
        vault.delete("tok_3")
        
        mock_table.delete_item.assert_any_call(Key={"token": f"mask-rev:tenant-a:{data3_hash}"})
        mock_table.delete_item.assert_any_call(Key={"token": "mask:tenant-a:tok_3"})


# Memcached Tests

@mock.patch.dict(os.environ, {"MASK_MEMCACHED_HOST": "test-box", "MASK_MEMCACHED_PORT": "2222"})
class TestMemcachedVault:

    def test_init_connects_to_pymemcache(self):
        with mock.patch("pymemcache.client.base.Client") as mock_client:
            vault = MemcachedVault()
            mock_client.assert_called_once_with(("test-box", 2222))

    def test_store_and_retrieve_and_delete(self):
        with mock.patch("pymemcache.client.base.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            
            vault = MemcachedVault()
            
            # test store
            from mask_privacy.core.vault import _hash_plaintext
            ts_hash = _hash_plaintext("top_secret")
            vault.store("tok_A", "top_secret", 300, pt_hash=ts_hash)
            
            # Verify set_multi was called (once for all 3 keys)
            mock_client.set_multi.assert_called_once()
            keys_written = mock_client.set_multi.call_args[0][0]
            assert "mask:tenant-a:tok_A" in keys_written
            assert f"mask-rev:tenant-a:{ts_hash}" in keys_written
            assert "mask-hash:tenant-a:tok_A" in keys_written
            
            # test retrieve
            mock_client.get.return_value = b"bytes_secret"
            assert vault.retrieve("tok_A") == "bytes_secret"
            
            # test delete — use side_effect to return the pt_hash for mask-hash lookup
            def mock_get_for_delete(key):
                if key == f"mask-hash:tenant-a:tok_A":
                    return ts_hash.encode("utf-8")
                return b"bytes_secret"
            mock_client.get.side_effect = mock_get_for_delete
            
            vault.delete("tok_A")
            # Verify delete_multi was called
            mock_client.delete_multi.assert_called_once()
            keys_deleted = mock_client.delete_multi.call_args[0][0]
            assert "mask:tenant-a:tok_A" in keys_deleted
            assert "mask-hash:tenant-a:tok_A" in keys_deleted
            assert f"mask-rev:tenant-a:{ts_hash}" in keys_deleted
