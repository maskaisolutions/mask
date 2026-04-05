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
import {
  FIRST_NAMES as _BIJECTIVE_NAMES,
  CONNECTORS as _BIJECTIVE_CONNECTORS,
  SURNAME_ROOTS as _BIJECTIVE_ROOTS,
  SURNAME_SUFFIXES as _BIJECTIVE_SUFFIXES,
  SYLLABLES as _BIJECTIVE_SYLLABLES
} from './synthesisLibrary';


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
const _PHONE_RE = /(?<!\d)(?:\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}|\d{3}[\s\-.]?\d{4}|\+\d{2,3}[\s\-.]?\d{3}[\s\-.]?\d{3}[\s\-.]?\d{3,4})(?!\d)/;
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

/**
 * Return a deterministic 128-bit BigInt from HMAC(key, plaintext).
 *
 * Uses the first 16 bytes (128 bits) of the SHA-256 HMAC digest,
 * providing a namespace of 2^128 (~3.4 × 10^38). This replaces the
 * old nibble-by-nibble modulo-10 approach which suffered from severe
 * distribution bias in short fields (3-4 digits).
 */
async function _hmacInt(plaintext: string): Promise<bigint> {
  const masterKey = await _getMasterKey();
  const raw = crypto
    .createHmac('sha256', masterKey)
    .update(plaintext, 'utf-8')
    .digest();
  // Read first 16 bytes as a big-endian unsigned integer
  let result = 0n;
  for (let i = 0; i < 16; i++) {
    result = (result << 8n) | BigInt(raw[i]);
  }
  return result;
}

/**
 * Return *n* deterministic decimal digits from HMAC(key, plaintext).
 *
 * Uses full-integer division of a 128-bit HMAC-derived seed instead of
 * per-nibble modulo-10, which eliminates the distribution bias that
 * caused collisions in short numeric fields (routing numbers, SSN
 * suffixes). The offset parameter salts the input to derive
 * independent digit sequences from the same plaintext.
 */
async function _hmacDigits(plaintext: string, n: number, offset: number = 0): Promise<string> {
  const salted = offset ? `${plaintext}::${offset}` : plaintext;
  const seed = await _hmacInt(salted);
  const modulus = 10n ** BigInt(n);
  return (seed % modulus).toString().padStart(n, '0');
}

// ── Bijective Synthesis Engine ─────────────────────────────────────────────

export class FF1 {
  /** NIST SP 800-38G FF1 implementation (simplified for 64-bit domains). */
  constructor(private key: Buffer, private tweak: Buffer) {}

  encrypt(n: bigint): bigint {
    /** Encrypts 64-bit bigint n using FF1 (10 rounds). */
    let A = n >> 32n;
    let B = n & 0xFFFFFFFFn;
    const radix = 2n ** 32n;

    for (let i = 0; i < 10; i++) {
      const tweakInfoBuffer = Buffer.alloc(8);
      tweakInfoBuffer.writeUInt32BE(i, 0);
      tweakInfoBuffer.writeUInt32BE(Number(B), 4);
      const tweakInfoCombined = Buffer.concat([this.tweak, tweakInfoBuffer]);

      const h = crypto.createHmac('sha256', this.key)
        .update(tweakInfoCombined)
        .digest();
      
      const roundVal = BigInt(h.readUInt32BE(0));

      const Anext = B;
      const Bnext = (A + roundVal) % radix;
      A = Anext;
      B = Bnext;
    }

    return (A << 32n) | B;
  }

  decrypt(n: bigint): bigint {
    /** Decrypts 64-bit bigint n using FF1 (10 rounds in reverse). */
    let A = n >> 32n;
    let B = n & 0xFFFFFFFFn;
    const radix = 2n ** 32n;

    for (let i = 9; i >= 0; i--) {
      const tweakInfoBuffer = Buffer.alloc(8);
      tweakInfoBuffer.writeUInt32BE(i, 0);
      tweakInfoBuffer.writeUInt32BE(Number(A), 4);
      const tweakInfoCombined = Buffer.concat([this.tweak, tweakInfoBuffer]);

      const h = crypto.createHmac('sha256', this.key)
        .update(tweakInfoCombined)
        .digest();
      
      const roundVal = BigInt(h.readUInt32BE(0));

      const Bprev = A;
      const Aprev = (B - roundVal + radix) % radix;
      A = Aprev;
      B = Bprev;
    }

    return (A << 32n) | B;
  }
}

async function _getBijectiveTweak(): Promise<Buffer> {
  const masterKey = await _getMasterKey();
  let base = config.MASK_TENANT_ID;
  if (config.MASK_SALT_ROTATION !== 'NONE') {
    const now = new Date();
    if (config.MASK_SALT_ROTATION === 'MONTHLY') {
      base += `-${now.getUTCFullYear()}-${now.getUTCMonth() + 1}`;
    } else if (config.MASK_SALT_ROTATION === 'YEARLY') {
      base += `-${now.getUTCFullYear()}`;
    }
  }
  return crypto.createHmac('sha256', masterKey).update(base, 'utf-8').digest();
}

function _renderBijectivePerson(bits: bigint): string {
  /** Render a 64-bit cipher into a human-readable name (Bijective Synthesis). */
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

  // Format Shuffle
  if (formatIdx === 0) return `${first} ${conn} ${surname}-${paddedNumeric}`;
  if (formatIdx === 1) return `${surname}, ${first}-${paddedNumeric}`;
  if (formatIdx === 2) return `${first[0]}. ${surname}-${paddedNumeric}`;
  if (formatIdx === 3) return `${first} ${surname}-${paddedNumeric}`;
  
  return `${first} ${surname}-${paddedNumeric}`;
}

function _renderBijectiveLocation(bits: bigint): string {
  /** Render a 64-bit cipher into a bijective location name. */
  const s1 = Number(bits & 0x3FFn);
  const s2 = Number((bits >> 10n) & 0x3FFn);
  const s3 = Number((bits >> 20n) & 0x3FFn);
  const tag = Number((bits >> 30n) & 0xFFFn);

  const city = `${_BIJECTIVE_SYLLABLES[s1 % 1000]}${_BIJECTIVE_SYLLABLES[s2 % 1000].toLowerCase()}${_BIJECTIVE_SYLLABLES[s3 % 1000].toLowerCase()}`;
  return `${city}-${tag.toString().padStart(3, '0')}`;
}

// ── Legacy Semantic Token Banks (Redirected in Bijective Mode) ──────────────
// Seed lists are imported from semanticBanks.ts, maintaining architecture
// parity with python/semantic_banks.py

/** Return a deterministic item from an array using full 128-bit entropy. */
async function _pickFromArray(plaintext: string, array: string[]): Promise<string> {
   const seed = await _hmacInt(plaintext);
   return array[Number(seed % BigInt(array.length))];
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

  if (type === "ES_ID" || type === "ES_DNI") {
    const digits = `000${await _hmacDigits(text, 5)}`;
    return digits + _computeEsIdCheck(parseInt(digits, 10));
  }

  if (type === "PERSON" || type === "PERSON_NAME") {
      if (config.MASK_BIJECTIVE_MODE) {
        const canonical = text.toLowerCase().trim();
        const hash = crypto.createHash('sha256').update(canonical, 'utf-8').digest();
        const inputInt = hash.readBigUInt64BE(0);
        const masterKey = await _getMasterKey();
        const engine = new FF1(masterKey.slice(0, 16), await _getBijectiveTweak());
        const cipher = engine.encrypt(inputInt);
        return _renderBijectivePerson(cipher);
      }
      return `[TKN-PERSON-${await _hmacHex(text)}]`;
  }
  if (type === "LOCATION" || type === "PHYS_ADDRESS") {
      if (config.MASK_BIJECTIVE_MODE) {
        const canonical = text.toLowerCase().trim();
        const hash = crypto.createHash('sha256').update(canonical, 'utf-8').digest();
        const inputInt = hash.readBigUInt64BE(0);
        const masterKey = await _getMasterKey();
        const engine = new FF1(masterKey.slice(0, 16), await _getBijectiveTweak());
        const cipher = engine.encrypt(inputInt);
        return _renderBijectiveLocation(cipher);
      }
      return `[TKN-LOC-${await _hmacHex(text)}]`;
  }
  if (type === "ORGANIZATION") {
      return `[TKN-ORG-${await _hmacHex(text)}]`;
  }

  return `[TKN-${await _hmacHex(text)}]`;
}

export * from './fpe_utils';
