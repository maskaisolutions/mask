"""Tests for the AuditLogger (local-only)."""

import os
import logging
from unittest import mock

import pytest

from mask_privacy.telemetry.audit_logger import AuditLogger


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
    def test_flush_only_logs_locally(self, fresh_logger, caplog):
        """Events are flushed to local logs only (no remote forwarding)."""
        fresh_logger.log("encode", "t1")
        
        with caplog.at_level(logging.INFO, logger="mask.audit"):
            fresh_logger._flush()
            
            # Should emit JSON via the mask.audit logger
            assert "t1" in caplog.text
