"""
Asynchronous audit logger for Mask Privacy SDK.

Logs every tokenisation / detokenisation event *without* recording the
plaintext PII.  Events are batched and flushed to:
  - stdout / Python logging (default)
  - Customer SIEM (Datadog, Splunk) via structured JSON log lines

This module provides the SOC2 / HIPAA audit trail.
"""

import os
import json
import time
import hmac
import hashlib
import logging
import threading
import signal
from typing import Any, Dict, Optional, List

from mask_privacy.core.fpe import looks_like_token
from mask_privacy import config

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
        # Sanitize extra fields to prevent PII leakage into audit logs
        event.update(_deep_mask(extra))
    return event


def _deep_mask(obj: Any) -> Any:
    """Recursively redact any strings that do not look like Mask tokens.
    
    This ensures that if a developer accidentally passes cleartext PII in 
    the 'extra' fields, it is redacted before reaching the audit trail.
    """
    if obj is None:
        return None
    if isinstance(obj, str):
        return obj if looks_like_token(obj) else "[REDACTED]"
    if isinstance(obj, list):
        return [_deep_mask(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _deep_mask(v) for k, v in obj.items()}
    return obj


# AuditLogger – singleton, thread-safe

class AuditLogger:
    """Collects audit events and flushes them periodically."""

    _instance: Optional["AuditLogger"] = None
    _lock = threading.Lock()
    
    _flush_interval: float
    _running: bool
    _timer: Optional[threading.Timer]
    _buffer: List[Dict[str, Any]]
    _max_buffer_size: int
    _strict_mode: bool
    _buffer_full_warned: bool
    _handlers_registered: bool

    def __new__(cls) -> "AuditLogger":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init()
            return cls._instance

    def _init(self) -> None:
        self._flush_interval = 5.0  # seconds
        self._running = False
        self._timer: Optional[threading.Timer] = None
        self._buffer: List[Dict[str, Any]] = []
        self._max_buffer_size = config.MASK_AUDIT_MAX_BUFFER_SIZE
        self._strict_mode = config.MASK_AUDIT_LOG_STRICT
        self._buffer_full_warned = False
        self._handlers_registered = False

        # ── HMAC Signature Chain State ─────────────────────────────────────
        # The signing key is derived from MASK_MASTER_KEY so it is tied to
        # the deployment's identity. The genesis hash is all-zeros.
        _raw_key = os.environ.get("MASK_MASTER_KEY", "") or os.environ.get("MASK_ENCRYPTION_KEY", "")
        self._signing_key: bytes = hashlib.sha256(_raw_key.encode("utf-8")).digest()
        self._prev_sig: str = "0" * 64  # genesis hash (64 hex chars)

    @classmethod
    def reset(cls) -> None:
        """Clear the singleton instance. Useful for tests."""
        with cls._lock:
            instance = cls._instance
            if instance is not None:
                if instance._running:
                    instance.stop()
                cls._instance = None

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
        """Append an event to the buffer. Synchronous / Blocking if strict."""
        event = _make_event(action, token, data_type, agent, tool, extra or None)
        
        if self._strict_mode:
            # Backpressure: block until there's room
            while True:
                with self._lock:
                    if len(self._buffer) < self._max_buffer_size:
                        self._buffer.append(event)
                        break
                # Dangerous inside an event loop, but this is the sync API.
                time.sleep(0.05)
        else:
            with self._lock:
                if len(self._buffer) >= self._max_buffer_size:
                    if not self._buffer_full_warned:
                        logger.warning(
                            "AuditLogger buffer full (max=%d). Dropping newest events to prevent OOM.",
                            self._max_buffer_size
                        )
                        self._buffer_full_warned = True
                    return
                self._buffer.append(event)
        
        logger.debug("audit %s token=%s type=%s", action, token, data_type)

    async def alog(
        self,
        action: str,
        token: str,
        data_type: str = "opaque",
        agent: str = "",
        tool: str = "",
        **extra: Any,
    ) -> None:
        """Append an event to the buffer. Asynchronous / Non-blocking."""
        import asyncio
        event = _make_event(action, token, data_type, agent, tool, extra or None)
        
        if self._strict_mode:
            while True:
                with self._lock:
                    if len(self._buffer) < self._max_buffer_size:
                        self._buffer.append(event)
                        break
                await asyncio.sleep(0.05)
        else:
            with self._lock:
                if len(self._buffer) >= self._max_buffer_size:
                    return
                self._buffer.append(event)


    def start(self) -> None:
        """Begin periodic flushing and register signal handlers."""
        if self._running:
            return
        self._running = True
        self._schedule()

    def register_signals(self) -> None:
        """Register signal handlers for graceful shutdown."""
        if not self._handlers_registered:
            self._register_handlers()
            self._handlers_registered = True

    def _register_handlers(self) -> None:
        """Register SIGTERM and SIGINT to flush the buffer while preserving existing handlers."""
        original_sigterm = signal.getsignal(signal.SIGTERM)
        original_sigint = signal.getsignal(signal.SIGINT)

        def handle_signal(signum, frame):
            try:
                msg = f"\n[mask.audit] Signal {signum} received, flushing buffer...\n"
                os.write(1, msg.encode())
            except:
                pass
            
            self.stop()
            
            # Delegate to original handler if one existed
            original_handler = original_sigterm if signum == signal.SIGTERM else original_sigint
            if callable(original_handler):
                original_handler(signum, frame)
            elif original_handler == signal.SIG_DFL:
                signal.signal(signum, signal.SIG_DFL)
                os.kill(os.getpid(), signum)

        try:
            # Only register if we are in the main thread
            if threading.current_thread() is threading.main_thread():
                signal.signal(signal.SIGTERM, handle_signal)
                signal.signal(signal.SIGINT, handle_signal)
        except (ValueError, RuntimeError):
            pass

    def stop(self) -> None:
        """Stop periodic flushing and drain remaining events."""
        self._running = False
        timer = self._timer
        if timer:
            timer.cancel()
            self._timer = None
        self._flush()

    # -- internals ---------------------------------------------------------

    def _schedule(self) -> None:
        if not self._running:
            return
        timer = threading.Timer(self._flush_interval, self._tick)
        timer.daemon = True
        self._timer = timer
        timer.start()

    def _tick(self) -> None:
        self._flush()
        self._schedule()

    def _flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            events_to_flush = list(self._buffer)
            self._buffer.clear()
            self._buffer_full_warned = False

        audit_logger = logging.getLogger("mask.audit")

        # ── Secure File Handler (SOC 2 Audit Trail) ─────────────────────────
        # If MASK_SECURE_AUDIT_LOG_DIR is set, write to a rotating file
        # in addition to the standard Python logging channel.
        secure_log_dir = os.environ.get("MASK_SECURE_AUDIT_LOG_DIR", "")
        secure_file = None
        if secure_log_dir:
            os.makedirs(secure_log_dir, exist_ok=True)
            import datetime
            date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
            secure_file_path = os.path.join(secure_log_dir, f"mask-audit-{date_str}.ndjson")
            try:
                secure_file = open(secure_file_path, "a", encoding="utf-8")
            except OSError:
                pass

        if not audit_logger.handlers and not audit_logger.parent.handlers:  # type: ignore[union-attr]
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(message)s"))
            audit_logger.addHandler(handler)
            audit_logger.setLevel(logging.INFO)

        try:
            for event in events_to_flush:
                # ── HMAC Signature Chain ─────────────────────────────────────
                # sig_i = HMAC(signing_key, sig_{i-1} || JSON(event))
                body = json.dumps(event, default=str, sort_keys=True)
                sig_input = (self._prev_sig + body).encode("utf-8")
                sig = hmac.new(self._signing_key, sig_input, hashlib.sha256).hexdigest()
                signed_line = json.dumps({
                    **event,
                    "prev_sig": self._prev_sig,
                    "sig": sig,
                }, default=str, sort_keys=True)
                self._prev_sig = sig

                try:
                    audit_logger.info(signed_line)
                except Exception:
                    pass

                if secure_file:
                    try:
                        secure_file.write(signed_line + "\n")
                    except OSError:
                        pass
        finally:
            if secure_file:
                try:
                    secure_file.close()
                except OSError:
                    pass


def get_audit_logger() -> AuditLogger:
    """Return the process-wide audit logger singleton."""
    return AuditLogger()
