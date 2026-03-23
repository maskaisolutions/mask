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
  private _indexSecret: Buffer | null = null;

  private constructor() {}

  /** 
   * Return the singleton instance, initialising it if necessary.
   * This is asynchronous because key providers (KMS, etc.) might be async.
   */
  public static async getInstanceAsync(): Promise<CryptoEngine> {
    if (this._instance === null) {
      this._instance = new CryptoEngine();
      await this._instance._init();
    }
    return this._instance;
  }

  /** Legacy synchronous accessor — will throw if not already initialised. */
  public static getInstance(): CryptoEngine {
    if (this._instance === null) {
      throw new Error("CryptoEngine not initialised. Call getInstanceAsync() first.");
    }
    return this._instance;
  }

  /** Clear the singleton instance to force re-initialization (useful for key rotation). */
  public static reset(): void {
    this._instance = null;
  }

  private async _init(): Promise<void> {
    /**
     * Initialize the underlying Fernet engine.
     *
     * The encryption key is retrieved from the active KeyProvider.
     * If no key is available, a throwaway key is auto-generated for
     * local/test/demo use.
     */
    const provider = getKeyProvider();
    const keyFromProvider = await provider.getEncryptionKey();
    
    let key: string;
    if (!keyFromProvider) {
      if (process.env.MASK_STRICT_PROD === 'true') {
        throw new Error(
          'MASK_STRICT_PROD is enabled but MASK_ENCRYPTION_KEY is not set. ' +
          'Refusing to start with an auto-generated key in production mode.'
        );
      }
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
      this._fernet = new fernet.Secret(key);
    } catch (e) {
      throw new Error(
        "Invalid MASK_ENCRYPTION_KEY. Must be a valid url-safe base64-encoded " +
        "Fernet key."
      );
    }

    // Derive a separate secret for blind indexing (HMAC-SHA256)
    // We derive it from the master encryption key so we don't need a 3rd env var.
    const masterKey = await provider.getMasterKey() || key;
    this._indexSecret = cryptoNode.createHmac('sha256', masterKey).update("mask-blind-index").digest();
  }

  /** Return the secret used for HMAC-based blind indexing. */
  public async getIndexSecret(): Promise<Buffer> {
    if (!this._indexSecret) {
      await this._init();
    }
    return this._indexSecret!;
  }

  public encrypt(plaintext: string): string {
    /** Encrypt plaintext into a url-safe base64 string. */
    const token = new fernet.Token({
      secret: this._fernet,
      iv: Array.from(cryptoNode.randomBytes(16)) // use real randomness
    });
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
      console.error("Failed to decrypt vault payload. Check your MASK_ENCRYPTION_KEY. Inner error:", e);
      throw new MaskDecryptionError("Decryption failed");
    }
  }
}

/** Return the configured crypto engine singleton (Legacy sync wrapper). */
export function getCryptoEngine(): CryptoEngine {
  return CryptoEngine.getInstance();
}

/** Async-friendly accessor for the crypto engine. */
export async function getCryptoEngineAsync(): Promise<CryptoEngine> {
  return await CryptoEngine.getInstanceAsync();
}
