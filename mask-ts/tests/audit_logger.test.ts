import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { AuditLogger } from '../src/telemetry/audit_logger';
import * as fs from 'fs';

describe('TestAuditLogger', () => {
  let logger: AuditLogger;
  const dbPath = ":memory:";

  beforeEach(() => {
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    process.env.MASK_AUDIT_DB = dbPath;
    // @ts-ignore - reaching into private for test isolation
    AuditLogger._instance = null;
    logger = AuditLogger.getInstance();
  });

  afterEach(() => {
    logger.stop();
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    delete process.env.MASK_AUDIT_DB;
  });

  test('test_log_buffers_events', () => {
    logger.log("encode", "tok_123", "email");
    logger.log("decode", "tok_456", "ssn", "test_bot");
    
    // @ts-ignore
    const buffer = logger._buffer;
    expect(buffer.length).toBe(2);
    
    const evt1 = buffer[0];
    expect(evt1.action).toBe("encode");
    expect(evt1.token).toBe("tok_123");
    expect(evt1.data_type).toBe("email");

    const evt2 = buffer[1];
    expect(evt2.action).toBe("decode");
    expect(evt2.agent).toBe("test_bot");
  });

  test('test_flush_only_logs_locally', () => {
    const spy = jest.spyOn(console, 'info').mockImplementation(() => {});
    logger.log("encode", "t1");
    
    // @ts-ignore
    logger._flush();
    
    expect(spy).toHaveBeenCalled();
    const callArgs = spy.mock.calls[0][0];
    expect(callArgs).toContain("t1");
    expect(callArgs).toContain("encode");
    
    spy.mockRestore();
  });
});
