"""Tests for the AuditLogger telemetry forwarder."""

import os
import time
import json
import logging
import urllib.request
import urllib.error
from unittest import mock

import pytest

from mask.telemetry.audit_logger import AuditLogger


@pytest.fixture
def fresh_logger():
    """Returns a clean, non-singleton AuditLogger for testing."""
    logger = AuditLogger.__new__(AuditLogger)
    logger._init()
    # Speed up tests
    logger._flush_interval = 0.01 
    return logger


class TestAuditLogger:

    def test_log_buffers_events(self, fresh_logger):
        fresh_logger.log("encode", "tok_123", "email")
        fresh_logger.log("decode", "tok_456", "ssn", agent="test_bot")
        
        assert len(fresh_logger._buffer) == 2
        
        evt1 = fresh_logger._buffer[0]
        assert evt1["action"] == "encode"
        assert evt1["token"] == "tok_123"
        assert evt1["data_type"] == "email"

        evt2 = fresh_logger._buffer[1]
        assert evt2["action"] == "decode"
        assert evt2["agent"] == "test_bot"

    @mock.patch.dict(os.environ, clear=True)
    def test_flush_without_config_only_logs_locally(self, fresh_logger, caplog):
        """If API key is missing, events are only printed to local logs."""
        fresh_logger.log("encode", "t1")
        
        with caplog.at_level(logging.INFO, logger="mask.telemetry"):
            with mock.patch.object(fresh_logger, "_forward_to_control_plane") as mock_forward:
                fresh_logger._flush()
                
                # Should NOT attempt HTTP
                mock_forward.assert_not_called()
                
                # Should emit JSON locally
                assert "t1" in caplog.text

    @mock.patch.dict(os.environ, {
        "MASK_API_KEY": "sk_test_123",
        "MASK_CONTROL_PLANE_URL": "https://api.mask.example/v1/telemetry"
    }, clear=True)
    def test_flush_with_config_triggers_http_post(self, fresh_logger):
        """If configured, _flush should call _forward_to_control_plane."""
        fresh_logger.log("decode", "t2", "phone")
        
        with mock.patch.object(fresh_logger, "_forward_to_control_plane") as mock_forward:
            fresh_logger._flush()
            
            mock_forward.assert_called_once()
            args, _ = mock_forward.call_args
            assert args[0] == "https://api.mask.example/v1/telemetry"
            assert args[1] == "sk_test_123"
            
            # Events list
            events = args[2]
            assert len(events) == 1
            assert events[0]["token"] == "t2"

    @mock.patch("urllib.request.urlopen")
    def test_forward_daemon_handles_success(self, mock_urlopen, fresh_logger):
        """Verify the threading setup works for a 200 OK response."""
        events = [{"token": "t3"}]
        
        # Fake a 200 OK response
        mock_resp = mock.MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        fresh_logger._forward_to_control_plane("http://test", "sk_123", events)
        
        # Wait briefly for daemon thread to execute
        time.sleep(0.05)
        
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert req.headers["Authorization"] == "Bearer sk_123"
        
        payload = json.loads(req.data.decode("utf-8"))
        assert payload["events"][0]["token"] == "t3"

    @mock.patch("urllib.request.urlopen")
    def test_forward_daemon_swallows_network_errors(self, mock_urlopen, fresh_logger):
        """Verify that a network timeout does NOT raise an escaping exception."""
        events = [{"token": "t4"}]
        
        # Fake a network timeout
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        # This should execute and spawn the thread, but the exception inside the
        # thread must be caught and logged, not crash the test suite.
        fresh_logger._forward_to_control_plane("http://test", "sk_123", events)
        time.sleep(0.05)
        
        mock_urlopen.assert_called_once()
