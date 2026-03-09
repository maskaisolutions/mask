"""
Asynchronous audit logger for Mask Privacy SDK.

Logs every tokenisation / detokenisation event *without* recording the
plaintext PII.  Events are batched and flushed either to:
  - stdout / Python logging (default, free tier)
  - A Mask Control Plane SaaS endpoint (requires MASK_API_KEY)
  - Customer SIEM (Datadog, Splunk) via structured JSON log lines

This module provides the SOC2 / HIPAA audit trail.
"""

import os
import json
import time
import logging
import threading
import urllib.request
import urllib.error
import sqlite3
from typing import Any, Dict, Optional, List

logger = logging.getLogger("mask.telemetry")

# ---------------------------------------------------------------------------
# Event schema
# ---------------------------------------------------------------------------

def _make_event(
    action: str,
    token: str,
    data_type: str,
    agent: str = "",
    tool: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "ts": time.time(),
        "action": action,      # "encode" | "decode" | "expired" | "error"
        "token": token,
        "data_type": data_type, # "email" | "phone" | "ssn" | "opaque"
        "agent": agent,
        "tool": tool,
        **(extra or {}),
    }


# ---------------------------------------------------------------------------
# AuditLogger – singleton, thread-safe
# ---------------------------------------------------------------------------

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
        events_to_flush = []
        try:
            with sqlite3.connect(self._db_path, timeout=5.0) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM audit_events ORDER BY id ASC LIMIT 1000")
                rows = cursor.fetchall()
                
                if not rows:
                    return
                    
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
                    events_to_flush.append((row["id"], evt))
        except Exception as e:
            logger.error("Failed to read from audit sqlite db: %s", e)
            return

        # Always log to stdout / python logger for local debugging & SIEM ingestion
        for _, evt in events_to_flush:
            logger.info(json.dumps(evt, default=str))

        # Forward to Control Plane if configured
        api_key = os.environ.get("MASK_API_KEY")
        cp_url = os.environ.get("MASK_CONTROL_PLANE_URL")
        
        row_ids = [r[0] for r in events_to_flush]
        payload_events = [r[1] for r in events_to_flush]
        
        if api_key and cp_url:
            self._forward_to_control_plane(cp_url, api_key, payload_events, row_ids)
        else:
            # If no remote to forward to, just clear from local buffer
            self._delete_flushed_events(row_ids)

    def _delete_flushed_events(self, row_ids: List[int]) -> None:
        try:
            with sqlite3.connect(self._db_path, timeout=5.0) as conn:
                placeholders = ",".join("?" * len(row_ids))
                conn.execute(f"DELETE FROM audit_events WHERE id IN ({placeholders})", row_ids)
        except Exception as e:
            logger.error("Failed to cleanup flushed events from sqlite db: %s", e)

    def _forward_to_control_plane(
        self,
        url: str,
        api_key: str,
        events: list,
        row_ids: Optional[List[int]] = None,
    ) -> None:
        """Execute a non-blocking POST to the telemetry control plane."""
        payload = json.dumps({"events": events}, default=str).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "maskcloud/1.0",
            },
            method="POST",
        )
        
        # Fire and forget - do not let telemetry failures crash the agent thread
        def _post():
            success = False
            try:
                with urllib.request.urlopen(req, timeout=3.0) as response:
                    if response.status < 400:
                        success = True
                    else:
                        logger.warning("Telemetry forward failed: HTTP %s", response.status)
            except urllib.error.URLError as e:
                logger.debug("Telemetry forward error (non-fatal): %s", str(e))
            except Exception as e:
                logger.debug("Unexpected telemetry error: %s", str(e))
                
            # ONLY delete the events from the disk buffer if we successfully POSTed them
            if success and row_ids:
                self._delete_flushed_events(row_ids)

        # Spawn short-lived daemon thread to avoid blocking the flush timer
        t = threading.Thread(target=_post, daemon=True)
        t.start()


def get_audit_logger() -> AuditLogger:
    """Return the process-wide audit logger singleton."""
    return AuditLogger()
