/**
 * Core cryptography engine for Mask SDK.
 *
 * Provides a CryptoEngine singleton that handles Envelope Encryption,
 * ensuring that plaintext PII is encrypted locally before being
 * transmitted and stored in distributed vaults (Redis/Memcached/DynamoDB).
 *
 * Requires MASK_ENCRYPTION_KEY to be set in the environment.
 */

import * as process from 'process';
import { getKeyProvider } from './key_provider';

const fernet = require('fernet');
const cryptoNode = require('crypto');
import { MaskDecryptionError } from './exceptions';

export class CryptoEngine {
  private static _instance: CryptoEngine | null = null;
  private _fernet: any;

  private constructor() {
    this._init();
  }

  public static getInstance(): CryptoEngine {
    if (this._instance === null) {
      this._instance = new CryptoEngine();
    }
    return this._instance;
  }

  /** Clear the singleton instance to force re-initialization (useful for key rotation). */
  public static reset(): void {
    this._instance = null;
  }

  private _init(): void {
    /**
     * Initialize the underlying Fernet engine.
     *
     * The encryption key is retrieved from the active KeyProvider.
     * If no key is available, a throwaway key is auto-generated for
     * local/test/demo use.
     */
    const keyFromProvider = getKeyProvider().getEncryptionKey();
    let key: string;
    if (!keyFromProvider) {
      key = cryptoNode.randomBytes(32).toString('base64');
      process.env.MASK_ENCRYPTION_KEY = key;
      console.warn(
        "MASK_ENCRYPTION_KEY not set. Using a generated throwaway key. DO NOT USE THIS IN PRODUCTION."
      );
    } else {
      key = keyFromProvider;
    }

    try {
      // fernet Secret expects a base64 encoded string
      const secret = new fernet.Secret(key);
      this._fernet = secret;
    } catch (e) {
      throw new Error(
        "Invalid MASK_ENCRYPTION_KEY. Must be a valid url-safe base64-encoded " +
        "Fernet key."
      );
    }
  }

  public encrypt(plaintext: string): string {
    /** Encrypt plaintext into a url-safe base64 string. */
    const token = new fernet.Token({
      secret: this._fernet,
      time: Date.now(),
      iv: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] // Placeholder if needed, but fernet generates its own
    });
    // The fernet npm package encode returns a string
    return token.encode(plaintext);
  }

  public decrypt(ciphertext: string): string {
    /** Decrypt url-safe base64 ciphertext back to plaintext. */
    try {
      const token = new fernet.Token({
        secret: this._fernet,
        token: ciphertext,
        ttl: 0 // No TTL check by default to match Python's Fernet default
      });
      return token.decode();
    } catch (e) {
      console.error("Failed to decrypt vault payload. Check your MASK_ENCRYPTION_KEY.");
      throw new MaskDecryptionError("Decryption failed");
    }
  }
}

/** Return the configured crypto engine singleton. */
export function getCryptoEngine(): CryptoEngine {
  return CryptoEngine.getInstance();
}
