/**
 * Format-Preserving Encryption (FPE) token generation.
 *
 * Generates structurally valid, **deterministic** tokens that preserve the
 * format of the original data type so downstream tools, schemas, and
 * validators continue to work without modification.
 *
 * Determinism is achieved via HMAC-SHA256 keyed with a master key, ensuring
 * the same plaintext always produces the same token. This preserves entity
 * relationships for LLMs (e.g. "John" is always [TKN-abc]) without leaking
 * the identity.
 *
 * Supported formats:
 *   - Email  →  tkn-<hex>@email.com
 *   - Phone  →  +1-555-<7 digits>
 *   - SSN    →  000-00-<4 digits>
 *   - CC     →  4000-0000-0000-<4 digits>
 *   - Routing→  000000<3 digits>
 *   - Default→  [TKN-<hex>]
 */

import * as crypto from 'crypto';
import * as process from 'process';
import { getKeyProvider } from './key_provider';

// Master key management

let _masterKey: Buffer | null = null;

/** Return the HMAC master key, lazily initialised from the key provider. */
function _getMasterKey(): Buffer {
  if (_masterKey === null) {
    let raw = getKeyProvider().getMasterKey() || "";
    if (!raw) {
      // Auto-generate a session-local key (non-persistent)
      raw = crypto.randomBytes(32).toString('hex');
      process.env.MASK_MASTER_KEY = raw;
      console.warn(
        "MASK_MASTER_KEY not set. Using an ephemeral session key. " +
        "Tokens will NOT be reproducible across process restarts."
      );
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
const _PHONE_RE = /^\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}$|^\d{3}[\s\-.]?\d{4}$/;
const _SSN_RE = /^\d{3}-\d{2}-\d{4}$/;
const _CC_RE = /^(?:\d{4}[ \-]?){3}\d{4}$/;
const _ROUTING_RE = /^\d{9}$/;

// Deterministic helpers (HMAC-based)

/** Return *n* deterministic hex characters derived from HMAC(key, plaintext). */
function _hmacHex(plaintext: string, n: number = 8): string {
  const digest = crypto
    .createHmac('sha256', _getMasterKey())
    .update(plaintext, 'utf-8')
    .digest('hex');
  return digest.slice(0, n);
}

/** Return *n* deterministic decimal digits derived from HMAC(key, plaintext). */
function _hmacDigits(plaintext: string, n: number, offset: number = 0): string {
  const digest = crypto
    .createHmac('sha256', _getMasterKey())
    .update(plaintext, 'utf-8')
    .digest('hex');

  // Convert hex nibbles to digits via modulo-10
  const result: string[] = [];
  for (let i = offset; i < digest.length; i++) {
    const ch = digest[i];
    result.push((parseInt(ch, 16) % 10).toString());
    if (result.length === n) {
      break;
    }
  }

  // Safety: pad with zeros if digest is too short (shouldn't happen for SHA-256)
  while (result.length < n) {
    result.push("0");
  }
  return result.join("");
}

// Public API

/**
 * Return a **deterministic**, format-preserving token for rawText.
 *
 * The token is structurally compatible with the original data type
 * so that downstream schema validators, regex checks, and database
 * constraints continue to pass.
 */
export function generateFPEToken(rawText: string): string {
  const text = rawText.trim();

  if (_EMAIL_RE.test(text)) {
    return `tkn-${_hmacHex(text)}@email.com`;
  }

  if (_PHONE_RE.test(text)) {
    return `+1-555-${_hmacDigits(text, 7)}`;
  }

  if (_SSN_RE.test(text)) {
    return `000-00-${_hmacDigits(text, 4)}`;
  }

  // Standard 16-digit credit card (format: 4000-0000-0000-XXXX)
  if (_CC_RE.test(text)) {
    return `4000-0000-0000-${_hmacDigits(text, 4)}`;
  }

  // US ABA Routing Number (format: 000000XXX)
  if (_ROUTING_RE.test(text)) {
    return `000000${_hmacDigits(text, 3)}`;
  }

  // Opaque fallback
  return `[TKN-${_hmacHex(text)}]`;
}

/**
 * Regex that matches ANY valid Mask token.
 * Used for sub-string detokenization (finding tokens inside paragraphs).
 */
export const TOKEN_PATTERN = new RegExp(
  "tkn-[a-f0-9]{8,64}@email\\.com" +            // Email
  "|\\+1-555-\\d{7}" +                           // Phone
  "|000-00-\\d{4}" +                            // SSN
  "|4000-0000-0000-\\d{4}" +                    // CC
  "|000000\\d{3}" +                             // Routing
  "|\\[TKN-[a-f0-9]{8,64}\\]",                  // Opaque
  "g"
);

/**
 * Heuristic: return true if value appears to be a Mask token.
 */
export function looksLikeToken(value: string): boolean {
  const v = value.trim();

  // Email tokens: tkn-<hex>@email.com
  if (v.startsWith("tkn-") && v.endsWith("@email.com")) {
    return true;
  }

  // Phone tokens: +1-555-XXXXXXX  (555 is the standard fictional exchange)
  if (v.startsWith("+1-555-") && v.length === 14) {
    return true;
  }

  // SSN tokens: 000-00-XXXX  (area 000 is never assigned)
  if (v.startsWith("000-00-") && v.length === 11 && /^\d+$/.test(v.slice(7))) {
    return true;
  }

  // Credit card tokens: 4000-0000-0000-XXXX  (reserved test BIN)
  if (v.startsWith("4000-0000-0000-") && v.length === 19 && /^\d+$/.test(v.slice(15))) {
    return true;
  }

  // Routing tokens: 000000XXX  (invalid Fed symbol 0000)
  if (v.startsWith("000000") && v.length === 9 && /^\d+$/.test(v.slice(6))) {
    return true;
  }

  // Opaque fallback tokens: [TKN-<hex>]
  if (v.startsWith("[TKN-") && v.endsWith("]")) {
    return true;
  }

  return false;
}
