/**
 * Deterministic Pseudonymization (DP) token generation using NIST SP 800-38G FF1.
 */

import * as crypto from 'crypto';
import { config } from '../config';
import { getKeyProvider } from './key_provider';
import { MaskSecurityError } from './exceptions';
import { FF1 } from './ff1';
import {
  FIRST_NAMES as _BIJECTIVE_NAMES,
  CONNECTORS as _BIJECTIVE_CONNECTORS,
  SURNAME_ROOTS as _BIJECTIVE_ROOTS,
  SURNAME_SUFFIXES as _BIJECTIVE_SUFFIXES,
  SYLLABLES as _BIJECTIVE_SYLLABLES
} from './synthesisLibrary';

let _masterKey: Buffer | null = null;

async function _getMasterKey(): Promise<Buffer> {
  if (_masterKey === null) {
    const provider = getKeyProvider();
    let raw = await provider.getMasterKey();
    
    if (!raw) {
      raw = await provider.getEncryptionKey() || "";
    }

    if (!raw) {
      if (config.MASK_DEV_MODE) {
        raw = crypto.randomBytes(32).toString('hex');
        process.env.MASK_MASTER_KEY = raw;
      } else {
        throw new MaskSecurityError("MASK_MASTER_KEY not set.");
      }
    }
    _masterKey = Buffer.from(raw, 'utf-8');
  }
  return _masterKey;
}

export function resetMasterKey(): void {
  _masterKey = null;
}

async function _getAesKey(): Promise<Buffer> {
  // Salt the derivation with the tenant ID to guarantee per-tenant FF1
  // uniqueness — two tenants with the same plaintext must never produce
  // the same FPE token (cross-tenant collision prevention).
  const masterKey = await _getMasterKey();
  return crypto.createHmac('sha256', masterKey).update(config.MASK_TENANT_ID, 'utf-8').digest();
}

const _EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const _PHONE_RE = /(?<!\d)(?:\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}|\d{3}[\s\-.]?\d{4}|\+\d{2,3}[\s\-.]?\d{3}[\s\-.]?\d{3}[\s\-.]?\d{3,4})(?!\d)/;
const _SSN_RE = /^\d{3}-\d{2}-\d{4}$/;
const _CC_RE = /^(?:\d{4}[ \-]?){3}\d{4}$/;
const _ROUTING_RE = /^\d{9}$/;
const _ES_ID_RE = /^(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])$/;
const _IBAN_RE = /^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$/;

async function _hmacHex(plaintext: string, n: number = 8): Promise<string> {
  const masterKey = await _getMasterKey();
  const digest = crypto.createHmac('sha256', masterKey).update(plaintext, 'utf-8').digest('hex');
  return digest.slice(0, n);
}

// ── Bijective Synthesis Engine ─────────────────────────────────────────────

async function _getBijectiveTweak(): Promise<Buffer> {
  /**
   * Derive the FF1 tweak deterministically from the tenant ID.
   *
   * IMPORTANT: The tweak is intentionally time-independent. Historical use of
   * MASK_SALT_ROTATION (MONTHLY/YEARLY) caused permanent data loss when the
   * calendar rolled over because old tokens could no longer be re-derived.
   * Use MASK_KEYRING for key rotation instead; MASK_SALT_ROTATION is now a
   * no-op and will emit a console.warn if set to a non-NONE value.
   */
  if (config.MASK_SALT_ROTATION !== 'NONE') {
    console.warn(
      `[mask] MASK_SALT_ROTATION=${config.MASK_SALT_ROTATION} is deprecated and ignored. ` +
      'Time-based tweaks caused permanent data loss on month/year rollovers. ' +
      'Use MASK_KEYRING for key rotation instead.'
    );
  }
  const masterKey = await _getMasterKey();
  return crypto.createHmac('sha256', masterKey).update(config.MASK_TENANT_ID, 'utf-8').digest();
}

async function _encryptBijectiveFF1(text: string): Promise<bigint> {
  const canonical = text.toLowerCase().trim();
  const hash = crypto.createHash('sha256').update(canonical, 'utf-8').digest();
  // Hash to 64-bit int, then to 20-digit string
  const inputInt = hash.readBigUInt64BE(0);
  const inputStr = inputInt.toString().padStart(20, '0');
  
  const aesKey = await _getAesKey();
  const tweak = await _getBijectiveTweak();
  const engine = new FF1(aesKey, tweak, 10);
  
  const cipherStr = engine.encrypt(inputStr);
  return BigInt(cipherStr) % (2n ** 64n);
}

function _renderBijectivePerson(bits: bigint): string {
  const firstIdx = Number(bits & 0x7FFn);          // 11 bits (2048)
  const connIdx = Number((bits >> 11n) & 0x3Fn);    // 6 bits (64)
  const rootIdx = Number((bits >> 17n) & 0xFFFn);    // 12 bits (4096)
  const suffixIdx = Number((bits >> 29n) & 0x1FFn); // 9 bits (512)
  const tag = Number((bits >> 38n) & 0x3FFFn);      // 14 bits (16384)
  const formatIdx = Number((bits >> 52n) & 0xFn);   // 4 bits (16)

  const first = _BIJECTIVE_NAMES[firstIdx % _BIJECTIVE_NAMES.length];
  const conn = _BIJECTIVE_CONNECTORS[connIdx % _BIJECTIVE_CONNECTORS.length];
  const root = _BIJECTIVE_ROOTS[rootIdx % _BIJECTIVE_ROOTS.length];
  const suffix = _BIJECTIVE_SUFFIXES[suffixIdx % _BIJECTIVE_SUFFIXES.length];
  const surname = `${root}${suffix}`;
  const numeric = tag % 10000;

  const paddedNumeric = numeric.toString().padStart(4, '0');

  if (formatIdx === 0) return `${first} ${conn} ${surname}-${paddedNumeric}`;
  if (formatIdx === 1) return `${surname}, ${first}-${paddedNumeric}`;
  if (formatIdx === 2) return `${first[0]}. ${surname}-${paddedNumeric}`;
  if (formatIdx === 3) return `${first} ${surname}-${paddedNumeric}`;
  
  return `${first} ${surname}-${paddedNumeric}`;
}

function _renderBijectiveLocation(bits: bigint): string {
  const s1 = Number(bits & 0x3FFn);
  const s2 = Number((bits >> 10n) & 0x3FFn);
  const s3 = Number((bits >> 20n) & 0x3FFn);
  const tag = Number((bits >> 30n) & 0xFFFn);

  const city = `${_BIJECTIVE_SYLLABLES[s1 % 1000]}${_BIJECTIVE_SYLLABLES[s2 % 1000].toLowerCase()}${_BIJECTIVE_SYLLABLES[s3 % 1000].toLowerCase()}`;
  return `${city}-${tag.toString().padStart(3, '0')}`;
}

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

function _stripCcSeparators(text: string): string {
  return text.replace(/[\s\-]/g, '');
}

export async function generateDPToken(rawText: string, entityType: string = 'UNKNOWN'): Promise<string> {
  const text = rawText.trim();
  let type = (entityType || "UNKNOWN").toUpperCase();

  if (type === "UNKNOWN") {
    if (_EMAIL_RE.test(text)) type = "EMAIL_ADDRESS";
    else if (_SSN_RE.test(text)) type = "US_SSN";
    else if (_CC_RE.test(text)) type = "CREDIT_CARD";
    else if (_ROUTING_RE.test(text)) type = "US_ROUTING_NUMBER";
    else if (_ES_ID_RE.test(text)) type = "ES_ID";
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
    const digits = text.replace(/\D/g, "");
    if (digits.length >= 7) {
      const last7 = digits.slice(-7);
      const engine = new FF1(await _getAesKey(), Buffer.from("PHONE"), 10);
      const enc = engine.encrypt(last7);
      return `+${cc}-555-${enc}`;
    }
  }

  if (type === "US_SSN") {
    const digits = text.replace(/-/g, "");
    if (digits.length === 9) {
      const engine = new FF1(await _getAesKey(), Buffer.from("US_SSN"), 10);
      const enc = engine.encrypt(digits);
      return `${enc.slice(0,3)}-${enc.slice(3,5)}-${enc.slice(5,9)}`;
    }
  }

  if (type === "CREDIT_CARD" || type === "CREDIT_CARD_NUMBER") {
    const digits = _stripCcSeparators(text);
    if (digits.length === 16) {
      const bin6 = digits.slice(0, 6);
      const last4 = digits.slice(12, 16);
      const middle6 = digits.slice(6, 12);
      
      const engine = new FF1(await _getAesKey(), Buffer.from("CREDIT_CARD"), 10);
      const encMiddle = engine.encrypt(middle6);
      
      const base15 = bin6 + encMiddle + last4.slice(0, 3);
      const checkDig = _computeLuhnDigit(base15);
      const full = bin6 + encMiddle + last4.slice(0, 3) + checkDig;
      return `${full.slice(0, 4)}-${full.slice(4, 8)}-${full.slice(8, 12)}-${full.slice(12, 16)}`;
    } else {
      const fallbackDigits = digits.padEnd(16, '0').slice(0, 16);
      const engine = new FF1(await _getAesKey(), Buffer.from("CREDIT_CARD"), 10);
      const encMiddle = engine.encrypt(fallbackDigits.slice(6, 12));
      const full = fallbackDigits.slice(0, 6) + encMiddle + fallbackDigits.slice(12);
      return `${full.slice(0, 4)}-${full.slice(4, 8)}-${full.slice(8, 12)}-${full.slice(12, 16)}`;
    }
  }

  if (type === "US_ROUTING_NUMBER" || type === "US_ABA_ROUTING") {
    if (text.length === 9 && /^\d+$/.test(text)) {
      const engine = new FF1(await _getAesKey(), Buffer.from("US_ROUTING"), 10);
      return engine.encrypt(text);
    }
  }

  if (type === "INTL_BANK_IBAN" || type === "IBAN_CODE") {
    const countryCode = (text.length >= 2 && /[a-zA-Z]{2}/.test(text.slice(0, 2))) ? text.slice(0, 2).toUpperCase() : "US";
    return `${countryCode}00${(await _hmacHex(text, 8)).toUpperCase()}`;
  }

  if (type === "ES_ID" || type === "ES_DNI") {
    let digits = text.toUpperCase().replace(/[A-Z]/g, "");
    if (digits) {
      digits = digits.padStart(8, "0");
      const engine = new FF1(await _getAesKey(), Buffer.from("ES_ID"), 10);
      const enc = engine.encrypt(digits.slice(-5));
      const tokenDigits = `000${enc}`;
      return tokenDigits + _computeEsIdCheck(parseInt(tokenDigits, 10));
    }
  }

  if (type === "PERSON" || type === "PERSON_NAME") {
      if (config.MASK_BIJECTIVE_MODE) {
        const cipherBits = await _encryptBijectiveFF1(text);
        return _renderBijectivePerson(cipherBits);
      }
      return `[TKN-PERSON-${await _hmacHex(text)}]`;
  }
  if (type === "LOCATION" || type === "PHYS_ADDRESS") {
      if (config.MASK_BIJECTIVE_MODE) {
        const cipherBits = await _encryptBijectiveFF1(text);
        return _renderBijectiveLocation(cipherBits);
      }
      return `[TKN-LOC-${await _hmacHex(text)}]`;
  }
  if (type === "ORGANIZATION") {
      return `[TKN-ORG-${await _hmacHex(text)}]`;
  }

  return `[TKN-${await _hmacHex(text)}]`;
}

export const generateFPEToken = generateDPToken;

export * from './fpe_utils';
