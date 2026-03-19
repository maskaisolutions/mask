/**
 * Explicit Client initialization for the Mask SDK.
 *
 * Provides MaskClient — a unified, explicitly-configured client that
 * bundles vault, crypto, scanner, and audit logger into a single object.
 */

import { BaseVault, getVault, decode, encode, detokenizeText } from './core/vault';
import { CryptoEngine, getCryptoEngine } from './core/crypto';
import { PresidioScanner, getScanner } from './core/scanner';
import { generateFPEToken, looksLikeToken } from './core/fpe';
import { AuditLogger, getAuditLogger } from './telemetry/audit_logger';

export class MaskClient {
  public vault: BaseVault;
  public crypto: CryptoEngine;
  public scanner: PresidioScanner;
  public auditLogger: AuditLogger;
  /** backward compat alias */
  public logger: AuditLogger;
  public ttl: number;

  /**
   * Initialise the client with specific component instances.
   *
   * If an instance is not provided, the client will fall back to
   * the standard environment-configured singleton for that component.
   */
  constructor(options: {
    vault?: BaseVault;
    crypto?: CryptoEngine;
    scanner?: PresidioScanner;
    auditLogger?: AuditLogger;
    ttl?: number;
  } = {}) {
    this.vault = options.vault || getVault();
    this.crypto = options.crypto || getCryptoEngine();
    this.scanner = options.scanner || getScanner();
    this.auditLogger = options.auditLogger || getAuditLogger();
    this.logger = this.auditLogger;
    this.ttl = options.ttl || 600;

    // Ensure the audit logger is running
    this.auditLogger.start();
  }

  /**
   * Tokenise rawText, encrypt it, and store it in the vault.
   *
   * Includes deduplication: if the same plaintext has been encoded
   * before and the token is still active, the existing token is returned.
   */
  async encode(rawText: string): Promise<string> {
    // Token Guard: never re-encode a value that is already a Mask token
    if (looksLikeToken(rawText)) {
      return rawText;
    }

    // Normalise whitespace so " Alice " and "Alice" share the same hash
    const text = rawText.trim();

    // 1. Deduplication check
    // We'll use the vault methods directly here to match Python client logic
    const cryptoSub = require('crypto');
    const ptHash = cryptoSub.createHash('sha256').update(text, 'utf-8').digest('hex');

    const existingToken = await this.vault.getTokenByPlaintextHash(ptHash);
    if (existingToken && (await this.vault.retrieve(existingToken)) !== null) {
      this.logger.log("encode", existingToken, "opaque");
      return existingToken;
    }

    // 2. Generate deterministic token
    const token = generateFPEToken(text);

    // 3. Encrypt
    const ciphertext = this.crypto.encrypt(text);

    // 4. Store with reverse lookup hash
    await this.vault.store(token, ciphertext, this.ttl, ptHash);

    this.logger.log("encode", token, "opaque");
    return token;
  }

  /** Retrieve token from vault and decrypt it. */
  async decode(token: string): Promise<string> {
    const ciphertext = await this.vault.retrieve(token);
    if (ciphertext === null) {
      this.logger.log("expired", token, "opaque");
      return token;
    }

    try {
      const plaintext = this.crypto.decrypt(ciphertext);
      this.logger.log("decode", token, "opaque");
      return plaintext;
    } catch (e) {
      this.logger.log("error", token, "opaque", "decryption_failed");
      return token;
    }
  }

  /** Scan text using the Waterfall pipeline and replace PII with FPE tokens. */
  async scanAndTokenize(text: string): Promise<string> {
    return await this.scanner.scanAndTokenize(text, {
      encodeFn: (val) => this.encode(val)
    });
  }

  /** Async wrapper for encode (parity with Python aencode). */
  async aencode(rawText: string): Promise<string> {
    return await this.encode(rawText);
  }

  /** Async wrapper for decode (parity with Python adecode). */
  async adecode(token: string): Promise<string> {
    return await this.decode(token);
  }

  /** Async wrapper for scanAndTokenize (parity with Python ascan_and_tokenize). */
  async ascanAndTokenize(text: string): Promise<string> {
    return await this.scanAndTokenize(text);
  }

  /** Find and replace all tokens within text with their plaintext. */
  async detokenizeText(text: string): Promise<string> {
    return await detokenizeText(text);
  }

  /** Async wrapper for detokenizeText (parity with Python adetokenize_text). */
  async adetokenizeText(text: string): Promise<string> {
    return await this.detokenizeText(text);
  }
}
