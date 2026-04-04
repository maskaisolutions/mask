/* global describe, test, expect */
import { getScanner } from '../src/index';

async function ascanAndTokenize(text: string, options: any = {}) {
    return getScanner().scanAndTokenize(text, options);
}

describe('Multilingual ID Hardening (TS)', () => {



  test('Locale-Aware Precision (ES_DNI)', async () => {
    // Spanish DNI in English context
    const raw = "My DNI is 12345678Z";
    const masked = await ascanAndTokenize(raw, { pipeline: ['dlp'] });
    
    // Should mask using the ES_DNI generator (starts with 000)
    expect(masked).toContain("000");
  });

});
