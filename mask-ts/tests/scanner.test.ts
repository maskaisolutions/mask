import { describe, test, expect } from '@jest/globals';
import { REGEX_PATTERNS, PresidioScanner } from '../src/core/scanner';

describe('TestInternationalPhonePatterns', () => {
  const pattern = new RegExp(REGEX_PATTERNS["PHONE_NUMBER_INTL"].source, 'g');

  test.each([
    "+44 20 7946 0958",
    "+44 7911 123456",
    "+442079460958",
    "+33 1 23 45 67 89",
    "+33 6 12 34 56 78",
    "+49 30 1234 5678",
    "+49 170 1234567",
  ])('test_intl_phone_match: %s', (number) => {
    pattern.lastIndex = 0;
    expect(pattern.test(number)).toBe(true);
  });

  test.each([
    "+1 555 123 4567",
    "020 7946 0958",
    "just some text",
  ])('test_intl_phone_no_match: %s', (nonMatch) => {
    pattern.lastIndex = 0;
    expect(pattern.test(nonMatch)).toBe(false);
  });
});

describe('TestUSRoutingNumber', () => {
  const pattern = new RegExp(REGEX_PATTERNS["US_ROUTING_NUMBER"].source, 'g');

  test('test_regex_matches_9_digit_number', () => {
    pattern.lastIndex = 0;
    expect(pattern.test("021000021")).toBe(true);
  });

  test('test_regex_does_not_match_8_digits', () => {
    pattern.lastIndex = 0;
    expect(pattern.test("word 12345678 word")).toBe(false);
  });

  test('test_aba_checksum_valid', () => {
    // @ts-ignore - accessing protected static for test
    expect(PresidioScanner._abaChecksum("021000021")).toBe(true);
  });

  test('test_aba_checksum_invalid', () => {
    // @ts-ignore
    expect(PresidioScanner._abaChecksum("123456789")).toBe(false);
  });

  test('test_aba_checksum_wrong_length', () => {
    // @ts-ignore
    expect(PresidioScanner._abaChecksum("12345")).toBe(false);
  });
});

describe('TestUSPassport', () => {
  const pattern = new RegExp(REGEX_PATTERNS["US_PASSPORT"].source, 'g');

  test.each([
    "C12345678",
    "A00000001",
    "Z99999999",
  ])('test_passport_match: %s', (passport) => {
    pattern.lastIndex = 0;
    expect(pattern.test(passport)).toBe(true);
  });

  test.each([
    "c12345678",
    "12345678A",
    "AB12345678",
    "A1234567",
  ])('test_passport_no_match: %s', (nonMatch) => {
    pattern.lastIndex = 0;
    expect(pattern.test(nonMatch)).toBe(false);
  });
});

describe('TestDateOfBirth', () => {
  const pattern = new RegExp(REGEX_PATTERNS["DATE_OF_BIRTH"].source, 'g');

  test.each([
    "01/15/1990",
    "12/31/2000",
    "06/01/1985",
    "1990-01-15",
    "2000-12-31",
    "1985-06-01",
  ])('test_dob_match: %s', (dob) => {
    pattern.lastIndex = 0;
    expect(pattern.test(dob)).toBe(true);
  });

  test.each([
    "13/01/1990",
    "00/15/1990",
    "01/32/1990",
    "1890-01-01",
    "2100-01-01",
  ])('test_dob_no_match: %s', (nonMatch) => {
    pattern.lastIndex = 0;
    expect(pattern.test(nonMatch)).toBe(false);
  });
});
