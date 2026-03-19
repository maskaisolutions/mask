import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { generateFPEToken, looksLikeToken, resetMasterKey } from '../src/core/fpe';

describe('TestFPETokenGeneration', () => {
  beforeEach(() => {
    resetMasterKey();
    process.env.MASK_MASTER_KEY = "test-key-for-deterministic-fpe";
  });

  afterEach(() => {
    resetMasterKey();
  });

  test('test_email_format', () => {
    const token = generateFPEToken("user@company.io");
    expect(token.endsWith("@email.com")).toBe(true);
    expect(token.startsWith("tkn-")).toBe(true);
    expect(token).toMatch(/^[^@]+@[^@]+\.[^@]+$/);
  });

  test('test_phone_format', () => {
    const token = generateFPEToken("+1-212-555-1234");
    expect(token.startsWith("+1-555-")).toBe(true);
    expect(token.length).toBe(14);
    expect(token).toMatch(/^\+1-555-\d{7}$/);
  });

  test('test_seven_digit_phone_format', () => {
    const token = generateFPEToken("555-1234");
    expect(token.startsWith("+1-555-")).toBe(true);
    expect(token.length).toBe(14);
  });

  test('test_ssn_format', () => {
    const token = generateFPEToken("123-45-6789");
    expect(token.startsWith("000-00-")).toBe(true);
    expect(token.length).toBe(11);
    expect(token).toMatch(/^\d{3}-\d{2}-\d{4}$/);
  });

  test('test_cc_format', () => {
    const token = generateFPEToken("4111-1111-1111-1111");
    expect(token.startsWith("4000-0000-0000-")).toBe(true);
    expect(token.length).toBe(19);
    expect(token).toMatch(/^(?:\d{4}[ \-]?){3}\d{4}$/);
  });

  test('test_routing_format', () => {
    const token = generateFPEToken("122000661");
    expect(token.startsWith("000000")).toBe(true);
    expect(token.length).toBe(9);
    expect(token).toMatch(/^\d{9}$/);
  });

  test('test_opaque_fallback', () => {
    const token = generateFPEToken("just some random string");
    expect(token.startsWith("[TKN-")).toBe(true);
    expect(token.endsWith("]")).toBe(true);
  });

  test('test_deterministic_same_input_same_output', () => {
    const t1 = generateFPEToken("a@b.com");
    const t2 = generateFPEToken("a@b.com");
    expect(t1).toBe(t2);
    expect(t1.endsWith("@email.com")).toBe(true);
  });

  test('test_different_inputs_different_tokens', () => {
    const t1 = generateFPEToken("alice@example.com");
    const t2 = generateFPEToken("bob@example.com");
    expect(t1).not.toBe(t2);
  });

  test('test_determinism_across_all_types', () => {
    const values = [
      "user@test.com",
      "+1-212-555-1234",
      "555-1234",
      "123-45-6789",
      "4111-1111-1111-1111",
      "122000661",
      "John Doe",
    ];
    for (const value of values) {
      expect(generateFPEToken(value)).toBe(generateFPEToken(value));
    }
  });

  test('test_whitespace_stripped_determinism', () => {
    expect(generateFPEToken(" someone@email.com ")).toBe(generateFPEToken("someone@email.com"));
  });
});

describe('TestLooksLikeToken', () => {
  test('test_email_token', () => {
    expect(looksLikeToken("tkn-abcd1234@email.com")).toBe(true);
  });

  test('test_phone_token', () => {
    expect(looksLikeToken("+1-555-1234567")).toBe(true);
  });

  test('test_ssn_token', () => {
    expect(looksLikeToken("000-00-1234")).toBe(true);
  });

  test('test_cc_token', () => {
    expect(looksLikeToken("4000-0000-0000-1234")).toBe(true);
  });

  test('test_routing_token', () => {
    expect(looksLikeToken("000000123")).toBe(true);
  });

  test('test_opaque_token', () => {
    expect(looksLikeToken("[TKN-abcd1234]")).toBe(true);
  });

  test('test_real_email_is_not_token', () => {
    expect(looksLikeToken("real@company.com")).toBe(false);
  });

  test('test_random_string_is_not_token', () => {
    expect(looksLikeToken("hello world")).toBe(false);
  });
});
