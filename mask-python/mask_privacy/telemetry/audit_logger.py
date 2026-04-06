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

from mask_privacy.core.fpe import is_unambiguously_safe_token
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
    instance_id: str = "",
) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "ts": time.time(),
        "action": action,
        "token": token,
        "data_type": data_type,
        "agent": agent,
        "tool": tool,
        "instance_id": instance_id,
    }
    if extra:
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
        return obj if is_unambiguously_safe_token(obj) else "[REDACTED]"
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
        # the deployment's identity.
        # The genesis hash is derived from a per-instance UUID4 rather than
        # all-zeros, allowing SOC 2 auditors to verify chain continuity and
        # prove that each runtime produces a distinct, non-forgeable chain.
        import uuid
        self._instance_id: str = str(uuid.uuid4())
        _raw_key = os.environ.get("MASK_MASTER_KEY", "") or os.environ.get("MASK_ENCRYPTION_KEY", "")
        self._signing_key: bytes = hashlib.sha256(_raw_key.encode("utf-8")).digest()
        # Genesis = HMAC(signing_key, instance_id) — unique and verifiable
        self._prev_sig: str = hmac.new(
            self._signing_key,
            self._instance_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

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

    def _get_overflow_path(self) -> str:
        d = os.environ.get("MASK_SECURE_AUDIT_LOG_DIR") or os.environ.get("TEMP") or "/tmp"
        return os.path.join(d, f"mask_audit_overflow_{self._instance_id}.ndjson")

    def _write_overflow(self, event: Dict[str, Any]) -> None:
        try:
            with open(self._get_overflow_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except OSError as e:
            if not getattr(self, '_overflow_file_warned', False):
                logger.error("Failed to write to audit overflow file: %s", e)
                self._overflow_file_warned = True

    def _consume_overflow(self, events: List[Dict[str, Any]]) -> None:
        path = self._get_overflow_path()
        if not os.path.exists(path):
            return
        processing_path = path + ".processing"
        with self._lock:
            try:
                os.replace(path, processing_path)
            except OSError:
                return
        try:
            with open(processing_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(json.loads(line))
            os.remove(processing_path)
        except Exception as e:
            logger.error("Failed to consume overflow: %s", e)

    def log(
        self,
        action: str,
        token: str,
        data_type: str = "opaque",
        agent: str = "",
        tool: str = "",
        **extra: Any,
    ) -> None:
        """Append an event to the buffer. Synchronous API."""
        event = _make_event(action, token, data_type, agent, tool, extra or None, self._instance_id)
        
        with self._lock:
            if len(self._buffer) >= self._max_buffer_size:
                if not self._buffer_full_warned:
                    logger.warning(
                        "AuditLogger buffer full (max=%d). Spooling to disk overflow to prevent OOM.",
                        self._max_buffer_size
                    )
                    self._buffer_full_warned = True
                self._write_overflow(event)
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
        """Append an event to the buffer. Asynchronous API."""
        event = _make_event(action, token, data_type, agent, tool, extra or None, self._instance_id)
        
        with self._lock:
            if len(self._buffer) >= self._max_buffer_size:
                self._write_overflow(event)
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
            events_to_flush = list(self._buffer)
            self._buffer.clear()
            self._buffer_full_warned = False

        self._consume_overflow(events_to_flush)
        if not events_to_flush:
            return

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
