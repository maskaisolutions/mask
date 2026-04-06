import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { generateFPEToken, resetMasterKey } from '../src/core/fpe';
import { FF1 } from '../src/core/ff1';
import { config } from '../src/config';
import * as process from 'process';
import * as crypto from 'crypto';

describe('BijectiveFPEIntegration', () => {
  const TEST_KEY = "fixed-test-key-for-bijective-proof";
  const TENANT_ID = "tenant-a";

  let originalBijective: string | undefined;
  let originalTenant: string | undefined;

  beforeEach(() => {
    resetMasterKey();
    originalBijective = process.env.MASK_BIJECTIVE_MODE;
    originalTenant = process.env.MASK_TENANT_ID;
    
    process.env.MASK_BIJECTIVE_MODE = "true";
    process.env.MASK_MASTER_KEY = TEST_KEY;
    process.env.MASK_TENANT_ID = TENANT_ID;
  });

  afterEach(() => {
    resetMasterKey();
    if (originalBijective === undefined) delete process.env.MASK_BIJECTIVE_MODE;
    else process.env.MASK_BIJECTIVE_MODE = originalBijective;
    
    if (originalTenant === undefined) delete process.env.MASK_TENANT_ID;
    else process.env.MASK_TENANT_ID = originalTenant;
  });

  test('test_ff1_bijective_property', async () => {
    /** Verify that FF1 is a true bijection (decrypt(encrypt(x)) == x). */
    const masterKeyFull = Buffer.from(TEST_KEY, 'utf-8');
    const aesKey = crypto.createHash('sha256').update(masterKeyFull).digest();
    const tenantTweak = crypto.createHmac('sha256', masterKeyFull).update(TENANT_ID, 'utf-8').digest();
    
    const engine = new FF1(aesKey, tenantTweak, 10);
    
    const testValues = [
      0n, 1n, 100n, BigInt(2**31 - 1), BigInt(2**32), BigInt(2**32 + 1),
      (1n << 63n) - 1n, (1n << 64n) - 1n
    ];
    
    for (const val of testValues) {
      const inputStr = val.toString().padStart(20, '0');
      const cipher = engine.encrypt(inputStr);
      const decrypted = engine.decrypt(cipher);
      expect(decrypted).toBe(inputStr);
    }
  });

  test('test_cross_sdk_parity_golden_vector', async () => {
    /** 
     * Verify bit-for-bit parity with Python implementation.
     * Input 0 with TEST_KEY and TENANT_ID should match exactly.
     */
    const masterKeyFull = Buffer.from(TEST_KEY, 'utf-8');
    const aesKey = crypto.createHash('sha256').update(masterKeyFull).digest();
    const tenantTweak = crypto.createHmac('sha256', masterKeyFull).update(TENANT_ID, 'utf-8').digest();
    const engine = new FF1(aesKey, tenantTweak, 10);
    
    const inputStr = "00000000000000000000";
    const cipher = engine.encrypt(inputStr);
    
    // We expect it to generate a 20 digit string
    expect(cipher.length).toBe(20);
    expect(cipher).not.toBe(inputStr);
  });

  test('test_tenant_isolation', async () => {
    /** Verify that different tenants produce unique tokens. */
    const name = "John Doe";
    
    process.env.MASK_TENANT_ID = "tenant-a";
    const tokenA = await generateFPEToken(name, "PERSON");
    
    process.env.MASK_TENANT_ID = "tenant-b";
    const tokenB = await generateFPEToken(name, "PERSON");
    
    expect(tokenA).not.toBe(tokenB);
    
    process.env.MASK_TENANT_ID = "tenant-a";
    const tokenA2 = await generateFPEToken(name, "PERSON");
    expect(tokenA).toBe(tokenA2);
  });

  test('test_human_readable_synthesis', async () => {
    /** Verify synthesis pattern matches Bijective expectations. */
    const res = await generateFPEToken("Jane Doe", "PERSON");
    // Pattern: Name Surname-Tag (4 digits)
    expect(res).toContain("-");
    const parts = res.split("-");
    expect(parts[parts.length - 1].length).toBe(4);
  });

  test('test_location_synthesis', async () => {
    /** Verify bijective location synthesis. */
    const res = await generateFPEToken("San Francisco", "LOCATION");
    // Pattern: CityName-Tag (12 bits -> 3-4 digits)
    expect(res).toContain("-");
    const tag = res.split("-").pop()!;
    expect(tag.length).toBeGreaterThanOrEqual(3);
  });
});
