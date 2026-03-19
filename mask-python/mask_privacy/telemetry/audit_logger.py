"""
Asynchronous audit logger for Mask Privacy SDK.

Logs every tokenisation / detokenisation event *without* recording the
plaintext PII.  Events are batched and flushed to:
  - stdout / Python logging (default)
  - Customer SIEM (Datadog, Splunk) via structured JSON log lines

This module provides the SOC2 / HIPAA audit trail.

NOTE: This SDK is LOCAL-FIRST. Audits are stored in a local
SQLite file (`.mask_audit.db`) and are NOT sent anywhere externally.
"""

import os
import json
import time
import logging
import threading
import sqlite3
from typing import Any, Dict, Optional, List

logger = logging.getLogger("mask.telemetry")

# Event schema

def _make_event(
    action: str,
    token: str,
    data_type: str,
    agent: str = "",
    tool: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "ts": time.time(),
        "action": action,      # "encode" | "decode" | "expired" | "error"
        "token": token,
        "data_type": data_type, # "email" | "phone" | "ssn" | "opaque"
        "agent": agent,
        "tool": tool,
    }
    if extra:
        event.update(extra)
    return event


# AuditLogger – singleton, thread-safe

class AuditLogger:
    """Collects audit events and flushes them periodically."""

    _instance: Optional["AuditLogger"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "AuditLogger":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init()
            return cls._instance

    def _init(self) -> None:
        self._db_path = os.environ.get("MASK_AUDIT_DB", ".mask_audit.db")
        self._flush_interval = 5.0  # seconds
        self._running = False
        self._timer: Optional[threading.Timer] = None
        # In-memory buffer retained for local inspection and unit tests.
        self._buffer: List[Dict[str, Any]] = []
        # Allow operators to disable on-disk audit persistence entirely
        # (for environments where storing token identifiers locally is not
        # permitted). When disabled, events are still emitted via the logger
        # but never written to SQLite.
        self._db_disabled = os.environ.get("MASK_DISABLE_AUDIT_DB", "").lower() in {
            "1",
            "true",
            "yes",
        }
        
        if self._db_disabled:
            logger.info(
                "MASK_DISABLE_AUDIT_DB is set – audit events will not be "
                "persisted to SQLite on disk."
            )
            return

        # Init SQLite tables when persistence is enabled
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL,
                    action TEXT,
                    token TEXT,
                    data_type TEXT,
                    agent TEXT,
                    tool TEXT,
                    extra_json TEXT
                )
                """
            )
            conn.commit()

    # -- public API --------------------------------------------------------

    def log(
        self,
        action: str,
        token: str,
        data_type: str = "opaque",
        agent: str = "",
        tool: str = "",
        **extra: Any,
    ) -> None:
        """Append an event to the sqlite buffer (durable when enabled)."""
        event = _make_event(action, token, data_type, agent, tool, extra or None)
        self._buffer.append(event)

        extra_json = json.dumps(extra) if extra else None

        if not self._db_disabled:
            try:
                with sqlite3.connect(self._db_path, timeout=5.0) as conn:
                    conn.execute(
                        "INSERT INTO audit_events (ts, action, token, data_type, agent, tool, extra_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (time.time(), action, token, data_type, agent, tool, extra_json),
                    )
            except Exception as e:
                logger.error("Failed to write audit event to sqlite buffer: %s", e)

        logger.debug("audit %s token=%s type=%s", action, token, data_type)

    def start(self) -> None:
        """Begin periodic flushing (call once at process startup)."""
        if self._running:
            return
        self._running = True
        self._schedule()

    def stop(self) -> None:
        """Stop periodic flushing and drain remaining events."""
        self._running = False
        if self._timer:
            self._timer.cancel()
        self._flush()

    # -- internals ---------------------------------------------------------

    def _schedule(self) -> None:
        if not self._running:
            return
        self._timer = threading.Timer(self._flush_interval, self._tick)
        self._timer.daemon = True
        self._timer.start()

    def _tick(self) -> None:
        self._flush()
        self._schedule()

    def _flush(self) -> None:
        if self._db_disabled:
            # When persistence is disabled there is nothing to drain from disk.
            return

        # Pull up to 1000 events from the DB
        try:
            with sqlite3.connect(self._db_path, timeout=5.0) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM audit_events ORDER BY id ASC LIMIT 1000")
                rows = cursor.fetchall()
                
                if not rows:
                    return

                # Log to stdout / python logger for local debugging & SIEM ingestion
                for row in rows:
                    evt = {
                        "ts": row["ts"],
                        "action": row["action"],
                        "token": row["token"],
                        "data_type": row["data_type"],
                        "agent": row["agent"],
                        "tool": row["tool"],
                    }
                    if row["extra_json"]:
                        evt.update(json.loads(row["extra_json"]))
                    logger.info(json.dumps(evt, default=str))

                # Clean up flushed events from the local DB
                row_ids = [row["id"] for row in rows]
                placeholders = ",".join("?" * len(row_ids))
                conn.execute(f"DELETE FROM audit_events WHERE id IN ({placeholders})", row_ids)
        except Exception as e:
            logger.error("Failed to flush audit events from sqlite db: %s", e)


def get_audit_logger() -> AuditLogger:
    """Return the process-wide audit logger singleton."""
    return AuditLogger()

