/**
 * Custom exception hierarchy for the Mask SDK.
 *
 * Provides specific exceptions so callers can implement targeted
 * retry/fallback logic instead of catching generic Error.
 */

export class MaskError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Raised when a vault backend (Redis, DynamoDB) is unreachable. */
export class MaskVaultConnectionError extends MaskError {}

/** Raised when CryptoEngine.decrypt() fails (bad key, corrupt data). */
export class MaskDecryptionError extends MaskError {}

/** Raised when spaCy / Presidio analysis exceeds the time budget. */
export class MaskNLPTimeout extends MaskError {}

/** Raised when mandatory security keys (MASK_MASTER_KEY, etc.) are missing. */
export class MaskSecurityError extends MaskError {}

/**
 * Raised when a newly generated token already maps to a *different* plaintext.
 *
 * This indicates a Birthday-Paradox collision in the deterministic pseudonymization
 * engine — two distinct plaintexts produced the same token.  The vault refuses to
 * overwrite existing PII, so the caller must handle the collision.
 */
export class TokenCollisionError extends MaskError {
  public readonly token: string;
  public readonly existingHash: string;
  public readonly incomingHash: string;

  constructor(token: string, existingHash: string, incomingHash: string) {
    super(
      `Token collision detected for token '${token}'. ` +
      `Existing plaintext hash '${existingHash.slice(0, 8)}…' conflicts with ` +
      `incoming hash '${incomingHash.slice(0, 8)}…'. ` +
      'Increase token entropy or adjust tenant salt configuration.'
    );
    this.token = token;
    this.existingHash = existingHash;
    this.incomingHash = incomingHash;
  }
}
