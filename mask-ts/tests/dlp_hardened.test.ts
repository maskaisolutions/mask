/* global describe, test, expect */
import { getScanner } from '../src/index';

async function ascanAndTokenize(text: string, options: any = {}) {
    return getScanner().scanAndTokenize(text, options);
}

describe('Multilingual ID Hardening (TS)', () => {

  test('Chinese ID Fragmentation Fix', async () => {
    // Valid 18-digit Chinese ID (with correct checksum '7')
    const raw = "My ID is 110101199003074477";
    const masked = await ascanAndTokenize(raw, { pipeline: ['dlp'] });
    
    // Should mask to a single CN_ID token with prefix 88000019900101
    expect(masked).toContain("88000019900101");
  });

  test('Fuzzy Fail-Safe (High Entropy)', async () => {
    // ID with a typo (checksum fails)
    const raw = "ID with typo: 110101199003074475";
    const masked = await ascanAndTokenize(raw, { pipeline: ['dlp'] });
    
    // Should still be masked (leaked if Priority 0 wasn't fuzzy)
    expect(masked).not.toContain("110101199003074475");
    expect(masked).toContain("88000019900101");
  });

  test('Locale-Aware Precision (ES_DNI)', async () => {
    // Spanish DNI in English context
    const raw = "My DNI is 12345678Z";
    const masked = await ascanAndTokenize(raw, { pipeline: ['dlp'] });
    
    // Should mask using the ES_DNI generator (starts with 000)
    expect(masked).toContain("000");
  });

});
