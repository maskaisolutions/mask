/**
 * Asynchronous audit logger for Mask Privacy SDK.
 *
 * Logs every tokenisation / detokenisation event *without* recording the
 * plaintext PII. Events are batched and flushed to:
 *   - stdout / Console (default)
 *   - Customer SIEM via structured JSON log lines
 *
 * Provides the SOC2 / HIPAA audit trail.
 */

import { config } from '../config';
import { looksLikeToken } from '../core/fpe_utils';

// ---------------------------------------------------------------------------
// Internal SDK Logger (replaces scattered console.info calls)
// ---------------------------------------------------------------------------

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 } as const;
type LogLevel = keyof typeof LOG_LEVELS;

function _getLogLevel(): LogLevel {
  const env = config.MASK_LOG_LEVEL;
  return (env in LOG_LEVELS) ? env as LogLevel : 'info';
}

/**
 * Lightweight internal logger matching Python's logging pattern.
 * Usage: `const log = getLogger('mask.scanner'); log.info('...');`
 */
export function getLogger(name: string) {
  const level = _getLogLevel();
  const threshold = LOG_LEVELS[level];

  const _log = (lvl: LogLevel, ...args: any[]) => {
    if (LOG_LEVELS[lvl] >= threshold) {
      const prefix = `[${name}]`;
      switch (lvl) {
        case 'debug': console.debug(prefix, ...args); break;
        case 'info':  console.info(prefix, ...args); break;
        case 'warn':  console.warn(prefix, ...args); break;
        case 'error': console.error(prefix, ...args); break;
      }
    }
  };

  return {
    debug: (...args: any[]) => _log('debug', ...args),
    info:  (...args: any[]) => _log('info', ...args),
    warn:  (...args: any[]) => _log('warn', ...args),
    error: (...args: any[]) => _log('error', ...args),
  };
}

// ---------------------------------------------------------------------------
// Audit Event Schema
// ---------------------------------------------------------------------------

/** Event schema helper */
function _makeEvent(
    action: string,
    token: string,
    dataType: string,
    agent: string = "",
    tool: string = "",
    extra: Record<string, any> | null = null
): Record<string, any> {
    const event: Record<string, any> = {
        ts: Date.now() / 1000,
        action,      // "encode" | "decode" | "expired" | "error"
        token,
        data_type: dataType, // "email" | "phone" | "ssn" | "opaque"
        agent,
        tool,
    };
    if (extra) {
        // Sanitize extra fields to prevent PII leakage into audit logs
        Object.assign(event, _deepMask(extra));
    }
    return event;
}

/**
 * Recursively redact any strings in an object that do not look like Mask tokens.
 * This ensures that if a developer accidentally passes cleartext PII in the
 * 'extra' fields, it is redacted before reaching the audit trail.
 */
function _deepMask(obj: any): any {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj === 'string') {
        return looksLikeToken(obj) ? obj : "[REDACTED]";
    }
    if (typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
        return obj.map(v => _deepMask(v));
    }

    const masked: Record<string, any> = {};
    for (const [k, v] of Object.entries(obj)) {
        masked[k] = _deepMask(v);
    }
    return masked;
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

const _logger = getLogger('mask.audit');

export class AuditLogger {
    private static _instance: AuditLogger | null = null;
    private _flushInterval: number = 5000; // ms
    private _running: boolean = false;
    private _timer: NodeJS.Timeout | null = null;
    private _isFlushing: boolean = false;
    private _buffer: Record<string, any>[] = [];
    private _maxBufferSize: number;
    private _strictMode: boolean;
    private _bufferFullWarned: boolean = false;
    private _shutdownRegistered: boolean = false;

    private constructor() {
        this._maxBufferSize = config.MASK_AUDIT_MAX_BUFFER_SIZE;
        this._strictMode = config.MASK_AUDIT_LOG_STRICT;
    }

    public static getInstance(): AuditLogger {
        if (this._instance === null) {
            this._instance = new AuditLogger();
        }
        return this._instance;
    }

    public log(
        action: string,
        token: string,
        dataType: string = "opaque",
        agent: string = "",
        tool: string = "",
        extra: Record<string, any> = {}
    ): void {
        /** Append an event to the memory buffer to be flushed asynchronously. */
        const event = _makeEvent(action, token, dataType, agent, tool, extra);
        
        if (this._buffer.length >= this._maxBufferSize) {
            if (!this._bufferFullWarned) {
                _logger.warn(
                    `AuditLogger buffer full (max=${this._maxBufferSize}). Performing emergency sync-flush to prevent data loss.`
                );
                this._bufferFullWarned = true;
            }
            // Emergency sync-flush to stdout to apply backpressure and prevent data loss
            this._flushSync();
        }
        
        this._buffer.push(event);
    }

    public start(): void {
        /** Begin periodic flushing (call once at process startup). */
        if (this._running) return;
        this._running = true;
        this._timer = setInterval(() => this._flush(), this._flushInterval);
        // Unref to allow process exit if only the audit logger is running
        if (this._timer && typeof this._timer.unref === 'function') {
            this._timer.unref();
        }

        // Register graceful shutdown handlers (once)
        // Skip in Jest to avoid leaking listeners between tests
        if (!this._shutdownRegistered && !process.env.JEST_WORKER_ID) {
            this._shutdownRegistered = true;
            const gracefulShutdown = () => {
                this._flushSync();
            };
            process.on('SIGTERM', gracefulShutdown);
            process.on('SIGINT', gracefulShutdown);
            process.on('beforeExit', gracefulShutdown);
        }
    }

    public async stop(): Promise<void> {
        /** Stop periodic flushing and drain remaining events. */
        this._running = false;
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
        await this._flush();
    }

    private async _flush(): Promise<void> {
        if (this._isFlushing || this._buffer.length === 0) return;
        this._isFlushing = true;
        try {
            const events = [...this._buffer];
            this._buffer = [];
            this._bufferFullWarned = false;

            for (const evt of events) {
                // Use a replacer to handle BigInt values which are not JSON-serializable by default
                const json = JSON.stringify(evt, (_, v) => typeof v === 'bigint' ? v.toString() : v);
                console.info(json);
            }
        } finally {
            this._isFlushing = false;
        }
    }

    /** Synchronous flush for use in signal handlers where async is unreliable. */
    private _flushSync(): void {
        if (this._buffer.length === 0) return;
        const events = [...this._buffer];
        this._buffer = [];
        for (const evt of events) {
            process.stdout.write(JSON.stringify(evt) + '\n');
        }
    }
}

/** Return the process-wide audit logger singleton. */
export function getAuditLogger(): AuditLogger {
    return AuditLogger.getInstance();
}
