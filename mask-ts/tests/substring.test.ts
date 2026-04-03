import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { encode, resetVault, detokenizeText } from '../src/core/vault';
import { resetMasterKey } from '../src/core/fpe';
import { deepDecode } from '../src/core/utils';
import * as process from 'process';

describe('TestSubstringDetokenization', () => {
  beforeEach(() => {
    process.env.MASK_VAULT_TYPE = "memory";
    resetVault();
    resetMasterKey();
    process.env.MASK_MASTER_KEY = "test-substring-key";
  });

  afterEach(() => {
    resetVault();
    resetMasterKey();
  });

  test('test_detokenize_text_with_embedded_tokens', async () => {
    const email = "alice@example.com";
    const phone = "+1-555-123-4567";
    
    const tEmail = await encode(email);
    const tPhone = await encode(phone);
    
    const paragraph = `Contact ${tEmail} at ${tPhone} today.`;
    const restored = await detokenizeText(paragraph);
    
    expect(restored).toContain(email);
    expect(restored).toContain(phone);
    expect(restored).toBe(`Contact ${email} at ${phone} today.`);
  });

  test('test_deep_decode_handles_paragraphs', async () => {
    const email = "bob@work.com";
    const tEmail = await encode(email);
    
    const data = {
        "email": tEmail,
        "body": `Hi, I am ${tEmail}. Please call me.`,
        "nested": [`Token: ${tEmail}`]
    };
    
    const decoded: any = await deepDecode(data);
    
    expect(decoded.email).toBe(email);
    expect(decoded.body).toBe(`Hi, I am ${email}. Please call me.`);
    expect(decoded.nested[0]).toBe(`Token: ${email}`);
  });

  test('test_detokenize_text_lenient', async () => {
    const bogus = "tkn-12345678@example.com";
    const paragraph = `Hello ${bogus}`;
    
    const restored = await detokenizeText(paragraph);
    expect(restored).toBe(paragraph);
  });
});
