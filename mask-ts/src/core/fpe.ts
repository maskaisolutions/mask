/**
 * Format-Preserving Encryption (FPE) token generation.
 *
 * Generates structurally valid, **deterministic** tokens that preserve the
 * format of the original data type so downstream tools, schemas, and
 * validators continue to work without modification.
 */

import * as crypto from 'crypto';
import * as process from 'process';
import { getKeyProvider } from './key_provider';
import { MaskSecurityError } from './exceptions';
import { looksLikeToken } from './fpe_utils';

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
      if (process.env.MASK_ALLOW_INSECURE_KEYS === "true") {
        // Auto-generate a session-local key (non-persistent)
        raw = crypto.randomBytes(32).toString('hex');
        process.env.MASK_MASTER_KEY = raw;
      } else {
        throw new MaskSecurityError(
          "MASK_MASTER_KEY not set. Set it or use MASK_ALLOW_INSECURE_KEYS=true for dev."
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
const _PHONE_RE = /^\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}$|^\d{3}[\s\-.]?\d{4}$/;
const _SSN_RE = /^\d{3}-\d{2}-\d{4}$/;
const _CC_RE = /^(?:\d{4}[ \-]?){3}\d{4}$/;
const _ROUTING_RE = /^\d{9}$/;

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

/**
 * Return a **deterministic**, format-preserving token for rawText.
 */
export async function generateFPEToken(rawText: string): Promise<string> {
  const text = rawText.trim();

  if (_EMAIL_RE.test(text)) {
    return `tkn-${await _hmacHex(text)}@email.com`;
  }

  if (_PHONE_RE.test(text)) {
    return `+1-555-${await _hmacDigits(text, 7)}`;
  }

  if (_SSN_RE.test(text)) {
    return `000-00-${await _hmacDigits(text, 4)}`;
  }

  if (_CC_RE.test(text)) {
    return `4000-0000-0000-${await _hmacDigits(text, 4)}`;
  }

  if (_ROUTING_RE.test(text)) {
    return `000000${await _hmacDigits(text, 3)}`;
  }

  return `[TKN-${await _hmacHex(text)}]`;
}

export * from './fpe_utils';
