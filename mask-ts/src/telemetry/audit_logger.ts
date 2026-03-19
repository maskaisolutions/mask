/**
 * Asynchronous audit logger for Mask Privacy SDK.
 *
 * Logs every tokenisation / detokenisation event *without* recording the
 * plaintext PII. Events are batched and flushed to:
 *   - stdout / Console (default)
 *   - Customer SIEM via structured JSON log lines
 *
 * NOTE: This SDK is LOCAL-FIRST. Audits are stored in a local
 * SQLite file (.mask_audit.db) and are NOT sent anywhere externally.
 */

import * as process from 'process';
import * as path from 'path';
import * as fs from 'fs';

// Deferring Database require to avoid Jest/Native module issues at top level

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
        Object.assign(event, extra);
    }
    return event;
}

export class AuditLogger {
    private static _instance: AuditLogger | null = null;
    private _dbPath: string;
    private _flushInterval: number = 5000; // ms
    private _running: boolean = false;
    private _timer: NodeJS.Timeout | null = null;
    private _buffer: Record<string, any>[] = [];
    private _dbDisabled: boolean;
    private _db: any; // better-sqlite3 Database

    private constructor() {
        this._dbPath = process.env.MASK_AUDIT_DB || ".mask_audit.db";
        this._dbDisabled = ["1", "true", "yes"].includes((process.env.MASK_DISABLE_AUDIT_DB || "").toLowerCase());

        if (this._dbDisabled) {
            console.info("MASK_DISABLE_AUDIT_DB is set – audit events will not be persisted to SQLite on disk.");
            return;
        }

        try {
            const Database = require('better-sqlite3');
            this._db = new Database(this._dbPath);
            this._db.exec(`
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
            `);
        } catch (e) {
            console.error(`Failed to initialize AuditLogger SQLite DB: ${e}`);
            this._dbDisabled = true;
        }
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
        /** Append an event to the sqlite buffer (durable when enabled). */
        const event = _makeEvent(action, token, dataType, agent, tool, extra);
        this._buffer.push(event);

        const extraJson = Object.keys(extra).length > 0 ? JSON.stringify(extra) : null;

        if (!this._dbDisabled && this._db) {
            try {
                const stmt = this._db.prepare(
                    "INSERT INTO audit_events (ts, action, token, data_type, agent, tool, extra_json) VALUES (?, ?, ?, ?, ?, ?, ?)"
                );
                stmt.run(Date.now() / 1000, action, token, dataType, agent, tool, extraJson);
            } catch (e) {
                console.error(`Failed to write audit event to sqlite buffer: ${e}`);
            }
        }
    }

    public start(): void {
        /** Begin periodic flushing (call once at process startup). */
        if (this._running) return;
        this._running = true;
        this._timer = setInterval(() => this._flush(), this._flushInterval);
    }

    public stop(): void {
        /** Stop periodic flushing and drain remaining events. */
        this._running = false;
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
        this._flush();
    }

    private _flush(): void {
        if (this._dbDisabled || !this._db) return;

        try {
            const rows = this._db.prepare("SELECT * FROM audit_events ORDER BY id ASC LIMIT 1000").all();
            if (rows.length === 0) return;

            for (const row of rows) {
                const evt: Record<string, any> = {
                    ts: row.ts,
                    action: row.action,
                    token: row.token,
                    data_type: row.data_type,
                    agent: row.agent,
                    tool: row.tool,
                };
                if (row.extra_json) {
                    try {
                        Object.assign(evt, JSON.parse(row.extra_json));
                    } catch (e) {}
                }
                console.info(JSON.stringify(evt));
            }

            const ids = rows.map((r: any) => r.id);
            const placeholders = ids.map(() => '?').join(',');
            this._db.prepare(`DELETE FROM audit_events WHERE id IN (${placeholders})`).run(...ids);
        } catch (e) {
            console.error(`Failed to flush audit events from sqlite db: ${e}`);
        }
    }
}

/** Return the process-wide audit logger singleton. */
export function getAuditLogger(): AuditLogger {
    return AuditLogger.getInstance();
}
