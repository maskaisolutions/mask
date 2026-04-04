/**
 * Format-Preserving Encryption (FPE) token generation.
 *
 * Generates structurally valid, **deterministic** tokens that preserve the
 * format of the original data type so downstream tools, schemas, and
 * validators continue to work without modification.
 */

import * as crypto from 'crypto';
import { config } from '../config';
import { getKeyProvider } from './key_provider';
import { MaskSecurityError } from './exceptions';

// Master key management

let _masterKey: Buffer | null = null;

/** Return the HMAC master key, lazily initialised from the key provider. */
async function _getMasterKey(): Promise<Buffer> {
  if (_masterKey === null) {
    const provider = getKeyProvider();
    let raw = await provider.getMasterKey();
    
    if (!raw) {
      // Fallback to encryption key if no master key is set
      raw = await provider.getEncryptionKey() || "";
    }

    if (!raw) {
      if (config.MASK_DEV_MODE) {
        // Auto-generate a session-local key (non-persistent)
        raw = crypto.randomBytes(32).toString('hex');
        // Update process.env for any other legacy paths that might check it
        process.env.MASK_MASTER_KEY = raw;
      } else {
        throw new MaskSecurityError(
          "MASK_MASTER_KEY not set. Set it or use MASK_DEV_MODE=true for dev."
        );
      }
    }
    _masterKey = Buffer.from(raw, 'utf-8');
  }
  return _masterKey;
}

/** Clear the cached master key. Useful in tests. */
export function resetMasterKey(): void {
  _masterKey = null;
}

// Detectors — order matters: first match wins

const _EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const _PHONE_RE = /(?<!\d)(?:\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}|\d{3}[\s\-.]?\d{4})(?!\d)/;
const _PHONE_INTL_RE = /(?<!\d)\+(?:[1-9]\d{0,3})[-.\s]?\(?\d{1,5}\)?(?:[-.\s]?\d{2,4}){2,4}(?!\d)/;
const _SSN_RE = /^\d{3}-\d{2}-\d{4}$/;
const _CC_RE = /^(?:\d{4}[ \-]?){3}\d{4}$/;
const _ROUTING_RE = /^\d{9}$/;
const _ES_ID_RE = /^(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])$/;
const _IBAN_RE = /^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$/;

// Deterministic helpers (HMAC-based)

/** Return *n* deterministic hex characters derived from HMAC(key, plaintext). */
async function _hmacHex(plaintext: string, n: number = 8): Promise<string> {
  const masterKey = await _getMasterKey();
  const digest = crypto
    .createHmac('sha256', masterKey)
    .update(plaintext, 'utf-8')
    .digest('hex');
  return digest.slice(0, n);
}

/** Return *n* deterministic decimal digits derived from HMAC(key, plaintext). */
async function _hmacDigits(plaintext: string, n: number, offset: number = 0): Promise<string> {
  const masterKey = await _getMasterKey();
  const digest = crypto
    .createHmac('sha256', masterKey)
    .update(plaintext, 'utf-8')
    .digest('hex');

  const result: string[] = [];
  for (let i = offset; i < digest.length; i++) {
    const ch = digest[i];
    result.push((parseInt(ch, 16) % 10).toString());
    if (result.length === n) break;
  }

  while (result.length < n) {
    result.push("0");
  }
  return result.join("");
}

// Public API

// Dictionary for Semantic NLP Faker Generation
const _FIRST_NAMES = ["Taylor", "Jordan", "Casey", "Morgan", "Riley", "Avery", "Rowan", "Quinn", "Charlie", "Peyton", "Blake", "Dakota", "Reese", "Skyler", "Finley", "Eden", "Harley", "Rory", "Emerson", "Remi"];
const _LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"];
const _CITIES = ["London", "Paris", "Berlin", "Tokyo", "Rome", "Madrid", "Vienna", "Sydney", "Toronto", "Chicago", "Seattle", "Austin", "Boston", "Denver", "Dallas", "Miami", "Seoul", "Dubai", "Mumbai", "Cairo"];

/** Return a deterministic item from an array. */
async function _pickFromArray(plaintext: string, array: string[]): Promise<string> {
   const digits = await _hmacDigits(plaintext, 8);
   const num = parseInt(digits, 10);
   return array[num % array.length];
}

/** Compute Luhn check digit */
function _computeLuhnDigit(partialNum: string): string {
    const digits = partialNum.split("").map(Number);
    let sum = 0;
    let shouldDouble = true; 
    for (let i = digits.length - 1; i >= 0; i--) {
        let digit = digits[i];
        if (shouldDouble) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        shouldDouble = !shouldDouble;
    }
    return ((10 - (sum % 10)) % 10).toString();
}



function _computeEsIdCheck(num: number): string {
  return "TRWAGMYFPDXBNJZSQVHLCKE"[num % 23];
}

// Public API

/**
 * Return a **deterministic**, format-preserving token for rawText using its entityType.
 */
export async function generateFPEToken(rawText: string, entityType: string = 'UNKNOWN'): Promise<string> {
  const text = rawText.trim();
  let type = (entityType || "UNKNOWN").toUpperCase();

  if (type === "UNKNOWN") {
    if (_EMAIL_RE.test(text)) type = "EMAIL_ADDRESS";
    else if (_SSN_RE.test(text)) type = "US_SSN";
    else if (_CC_RE.test(text)) type = "CREDIT_CARD";
    else if (_ROUTING_RE.test(text)) type = "US_ROUTING_NUMBER";
    else if (_ES_ID_RE.test(text)) type = "ES_DNI";
    else if (_IBAN_RE.test(text)) type = "INTL_BANK_IBAN";
    else if (_PHONE_RE.test(text)) type = "PHONE_NUMBER";
  }

  if (type === "EMAIL_ADDRESS" || type === "EMAIL_ADDR") {
    const parts = text.split("@");
    const domain = parts.length === 2 ? parts[1] : "email.com";
    return `tkn-${await _hmacHex(text)}@${domain}`;
  }

  if (type === "PHONE_NUMBER" || type === "PHONE_NUM" || type === "PHONE_NUM_INTL") {
    const m = text.match(/^\+([1-9]\d{0,3})/);
    const cc = m ? m[1] : "1";
    return `+${cc}-555-${await _hmacDigits(text, 7)}`;
  }

  if (type === "US_SSN") {
    return `000-00-${await _hmacDigits(text, 4)}`;
  }

  if (type === "CREDIT_CARD" || type === "CREDIT_CARD_NUMBER") {
    const base = `400000000000${await _hmacDigits(text, 3)}`;
    const checkDig = _computeLuhnDigit(base);
    const full = base + checkDig; 
    return `${full.slice(0,4)}-${full.slice(4,8)}-${full.slice(8,12)}-${full.slice(12,16)}`;
  }

  if (type === "US_ROUTING_NUMBER" || type === "US_ABA_ROUTING") {
    return `000000${await _hmacDigits(text, 3)}`;
  }

  if (type === "INTL_BANK_IBAN" || type === "IBAN_CODE") {
    const countryCode = (text.length >= 2 && /[a-zA-Z]{2}/.test(text.slice(0, 2))) ? text.slice(0, 2).toUpperCase() : "US";
    return `${countryCode}00${(await _hmacHex(text, 8)).toUpperCase()}`;
  }

  if (type === "ES_DNI") {
    const digits = `000${await _hmacDigits(text, 5)}`;
    return digits + _computeEsIdCheck(parseInt(digits, 10));
  }

  if (type === "PERSON" || type === "PERSON_NAME") {
      const f = await _pickFromArray(text, _FIRST_NAMES);
      const l = await _pickFromArray(text + "last", _LAST_NAMES);
      return `<PER:${f}_${l}>`;
  }
  if (type === "LOCATION" || type === "PHYS_ADDRESS") {
      const c = await _pickFromArray(text, _CITIES);
      return `<LOC:${c}>`;
  }
  if (type === "ORGANIZATION") {
      const c = await _pickFromArray(text, _LAST_NAMES);
      return `<ORG:${c}_Inc>`;
  }

  return `[TKN-${await _hmacHex(text)}]`;
}

export * from './fpe_utils';
