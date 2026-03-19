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
