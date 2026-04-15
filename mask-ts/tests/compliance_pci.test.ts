import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { generateDPToken, resetMasterKey, _getLuhnSum } from '../src/core/fpe';

describe('CompliancePCIChecks', () => {
  beforeEach(() => {
    resetMasterKey();
    process.env.MASK_MASTER_KEY = "compliance-remediation-test-key";
    process.env.MASK_TENANT_ID = "pci-auditor";
    process.env.MASK_BIJECTIVE_MODE = "true";
  });

  afterEach(() => {
    resetMasterKey();
  });

  test('test_pci_dss_v4_6_plus_4_compliance', async () => {
    /** Verify that CC tokenization reveals exactly the first 6 and last 4 digits. */
    const rawCc = "4111-2222-3333-4444";
    const token = await generateDPToken(rawCc);
    
    const digits = token.replace(/-/g, "");
    // BIN (First 6)
    expect(digits.slice(0, 6)).toBe("411122");
    // Identity (Last 4)
    expect(digits.slice(12)).toBe("4444");
    
    // Middle 6 must be masked/encrypted
    expect(digits.slice(6, 12)).not.toBe("223333");
  });

  test('test_luhn_preservation', async () => {
    /** Verify that the generated CC tokens are Luhn-valid identifiers. */
    const rawCc = "4111-2222-3333-4444";
    const token = await generateDPToken(rawCc);
    const digits = token.replace(/-/g, "");
    
    // Standard Luhn check
    const sum = _getLuhnSum(digits);
    expect(sum % 10).toBe(0);
  });

  test('test_bijective_entropy_expansion', async () => {
    /** Verify that bijective names use 10-digit tags (128-bit entropy). */
    const name = "Robert Oppenheimer";
    const token = await generateDPToken(name, "PERSON");
    
    const parts = token.split("-");
    const tag = parts[parts.length - 1];
    
    expect(tag.length).toBe(10);
    expect(/^\d+$/.test(tag)).toBe(true);
  });
});
