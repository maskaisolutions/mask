/**
 * Core cryptography engine for Mask SDK.
 *
 * Provides a CryptoEngine singleton that handles Envelope Encryption,
 * ensuring that plaintext PII is encrypted locally before being
 * transmitted and stored in distributed vaults (Redis/Memcached/DynamoDB).
 *
 * Uses AES-256-GCM (authenticated encryption) via native Node.js crypto.
 * Includes a compatibility layer to decrypt legacy Fernet-format tokens.
 *
 * Requires MASK_ENCRYPTION_KEY to be set in the environment.
 */

import { config } from '../config';
import * as cryptoNode from 'crypto';
import { getKeyProvider } from './key_provider';
import { MaskDecryptionError } from './exceptions';

// ---------------------------------------------------------------------------
// AES-256-GCM constants
// ---------------------------------------------------------------------------
const AES_KEY_BYTES = 32;        // 256 bits
const GCM_IV_BYTES = 12;         // 96-bit nonce (NIST recommended for GCM)
const GCM_AUTH_TAG_BYTES = 16;   // 128-bit auth tag
const GCM_ALGORITHM = 'aes-256-gcm';

// Prefix for new AES-GCM tokens to distinguish from legacy Fernet
const AES_GCM_PREFIX = 'aes:';

export class CryptoEngine {
  private static _instance: CryptoEngine | null = null;
  private _aesKey: Buffer | null = null;
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
     * Initialize the AES-256-GCM engine.
     *
     * The encryption key is retrieved from the active KeyProvider.
     * If no key is available, a throwaway key is auto-generated for
     * local/test/demo use.
     */
    const provider = getKeyProvider();
    const keyFromProvider = await provider.getEncryptionKey();
    
    let key: string;
    if (!keyFromProvider) {
      if (config.MASK_DEV_MODE) {
        key = cryptoNode.randomBytes(32).toString('base64');
        // We can't easily write back to config exports, but we can update process.env for the legacy path below
        process.env.MASK_ENCRYPTION_KEY = key;
        console.warn(
          "MASK_DEV_MODE is enabled. Using a generated throwaway key. " +
          "DO NOT USE THIS IN PRODUCTION — tokens will be lost on restart."
        );
      } else {
        throw new Error(
          'MASK_ENCRYPTION_KEY is not set. Set MASK_ENCRYPTION_KEY to a valid ' +
          'encryption key, or set MASK_DEV_MODE=true to use an ephemeral throwaway key.'
        );
      }
    } else {
      key = keyFromProvider;
    }

    // Derive a 32-byte AES key from the provided key material.
    // This normalises any key format (Fernet base64, raw base64, etc.)
    // into a consistent 32-byte key via SHA-256 derivation.
    this._aesKey = cryptoNode.createHash('sha256').update(key).digest();

    // Derive a separate secret for blind indexing (HMAC-SHA256)
    // We derive it from the master encryption key so we don't need a 3rd env var.
    const masterKey = await provider.getMasterKey() || key;
    const salt = config.MASK_BLIND_INDEX_SALT;
    this._indexSecret = cryptoNode.createHmac('sha256', masterKey).update(salt).digest();
  }

  /** Return the secret used for HMAC-based blind indexing. */
  public async getIndexSecret(): Promise<Buffer> {
    if (!this._indexSecret) {
      await this._init();
    }
    return this._indexSecret!;
  }

  public encrypt(plaintext: string): string {
    /** Encrypt plaintext using AES-256-GCM. Returns prefixed base64 string. */
    if (!this._aesKey) {
      throw new Error("CryptoEngine not initialised. AES key missing.");
    }

    const iv = cryptoNode.randomBytes(GCM_IV_BYTES);
    const cipher = cryptoNode.createCipheriv(GCM_ALGORITHM, this._aesKey, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    // Wire format: iv (12) + authTag (16) + ciphertext (variable)
    const combined = Buffer.concat([iv, authTag, encrypted]);
    return AES_GCM_PREFIX + combined.toString('base64');
  }

  public decrypt(ciphertext: string): string {
    /** Decrypt ciphertext. Supports both new AES-GCM and legacy Fernet formats. */
    if (!this._aesKey) {
      throw new Error("CryptoEngine not initialised. AES key missing.");
    }

    try {
      if (ciphertext.startsWith(AES_GCM_PREFIX)) {
        return this._decryptAesGcm(ciphertext.slice(AES_GCM_PREFIX.length));
      }

      // Legacy path: attempt Fernet-format decryption
      return this._decryptLegacyFernet(ciphertext);
    } catch (e) {
      console.error("Failed to decrypt vault payload. Check your MASK_ENCRYPTION_KEY. Inner error:", e);
      throw new MaskDecryptionError("Decryption failed");
    }
  }

  /** Decrypt an AES-256-GCM token (base64 encoded). */
  private _decryptAesGcm(b64: string): string {
    const combined = Buffer.from(b64, 'base64');
    if (combined.length < GCM_IV_BYTES + GCM_AUTH_TAG_BYTES) {
      throw new Error("Ciphertext too short for AES-GCM");
    }

    const iv = combined.subarray(0, GCM_IV_BYTES);
    const authTag = combined.subarray(GCM_IV_BYTES, GCM_IV_BYTES + GCM_AUTH_TAG_BYTES);
    const encrypted = combined.subarray(GCM_IV_BYTES + GCM_AUTH_TAG_BYTES);

    const decipher = cryptoNode.createDecipheriv(GCM_ALGORITHM, this._aesKey!, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);

    return decrypted.toString('utf8');
  }

  /**
   * Attempt to decrypt a legacy Fernet-format token.
   *
   * Fernet format: Version (1) || Timestamp (8) || IV (16) || Ciphertext (var) || HMAC (32)
   * All base64url-encoded.
   *
   * We try to use the `fernet` npm package if available, otherwise throw.
   */
  private _decryptLegacyFernet(ciphertext: string): string {
    let fernet: any;
    try {
      fernet = require('fernet');
    } catch (e) {
      throw new MaskDecryptionError(
        "Missing required optional dependency 'fernet' for legacy token decryption. " +
        "Please run 'npm install fernet' to support legacy tokens."
      );
    }

    try {
      // Reconstruct the original Fernet key from our AES key
      // This won't work if the key was derived differently, but it's a best-effort compat layer
      const token = new fernet.Token({
        secret: new fernet.Secret(config.MASK_ENCRYPTION_KEY || process.env.MASK_ENCRYPTION_KEY || ''),
        token: ciphertext,
        ttl: 0
      });
      return token.decode();
    } catch (e) {
      // If decryption fails, throw to caller
      throw new MaskDecryptionError(
        "Failed to decrypt legacy Fernet token. The key may have changed or the token is corrupt."
      );
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
