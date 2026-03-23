/**
 * Explicit Client initialization for the Mask SDK.
 *
 * Provides MaskClient — a unified, explicitly-configured client that
 * bundles vault, crypto, scanner, and audit logger into a single object.
 */

import { BaseVault, getVault, decode, encode, detokenizeText, _hashPlaintext } from './core/vault';
import { CryptoEngine, getCryptoEngine, getCryptoEngineAsync } from './core/crypto';
import { BaseScanner, getScanner } from './core/scanner';
import { looksLikeToken } from './core/fpe_utils';
import { AuditLogger, getAuditLogger } from './telemetry/audit_logger';

export class MaskClient {
  public vault: BaseVault;
  public crypto: CryptoEngine;
  public scanner: BaseScanner;
  public auditLogger: AuditLogger;
  /** backward compat alias */
  public logger: AuditLogger;
  public ttl: number;

  /**
   * Initialise the client with specific component instances.
   */
  constructor(options: {
    vault?: BaseVault;
    crypto?: CryptoEngine;
    scanner?: BaseScanner;
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
   * Static factory to create an initialized MaskClient.
   */
  public static async create(options: {
    vault?: BaseVault;
    crypto?: CryptoEngine;
    scanner?: BaseScanner;
    auditLogger?: AuditLogger;
    ttl?: number;
  } = {}): Promise<MaskClient> {
    const vault = options.vault || getVault();
    const crypto = options.crypto || await getCryptoEngineAsync();
    const scanner = options.scanner || getScanner();
    const auditLogger = options.auditLogger || getAuditLogger();
    
    return new MaskClient({
      vault,
      crypto,
      scanner,
      auditLogger,
      ttl: options.ttl
    });
  }

  /**
   * Tokenise rawText, encrypt it, and store it in the vault.
   */
  async encode(rawText: string): Promise<string> {
    if (looks_like_token_fallback(rawText)) {
      return rawText;
    }

    const text = rawText.trim();
    const indexSecret = await this.crypto.getIndexSecret();
    const ptHash = _hashPlaintext(text, indexSecret);

    const existingToken = await this.vault.getTokenByPlaintextHash(ptHash);
    if (existingToken && (await this.vault.retrieve(existingToken)) !== null) {
      this.logger.log("encode", existingToken, "opaque");
      return existingToken;
    }

    return await encode(rawText, { ttl: this.ttl });
  }

  /** Retrieve token from vault and decrypt it. */
  async decode(token: string): Promise<string> {
    try {
      return await decode(token);
    } catch (e) {
      this.logger.log("error", token, "opaque", "decryption_failed");
      if (process.env.MASK_STRICT_PROD === 'true') {
        throw e;
      }
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

/** Fallback to avoid early evaluation issues during circular loads */
function looks_like_token_fallback(val: string): boolean {
    try {
        return looksLikeToken(val);
    } catch {
        return false;
    }
}
