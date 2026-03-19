/**
 * Pluggable Key Provider abstraction for Mask SDK.
 *
 * Instead of hard-coded process.env, it reads with a pluggable interface so
 * enterprises can supply encryption keys from AWS KMS, Azure Key Vault,
 * HashiCorp Vault, or any custom source without exposing secrets in
 * environment variables.
 *
 * Usage:
 *
 *     // Default: reads from env vars (backwards compatible)
 *     const provider = getKeyProvider();
 *
 *     // Custom: inject your own provider
 *     setKeyProvider(new AwsKmsKeyProvider("alias/mask-key"));
 */

import * as process from 'process';

/**
 * Interface that all key providers must implement.
 *
 * A key provider supplies two secrets:
 *
 * - **encryptionKey**: Used by CryptoEngine (Fernet) to encrypt
 *   plaintext payloads before they enter the vault.
 * - **masterKey**: Used by generateFPEToken (HMAC-SHA256) to
 *   derive deterministic, format-preserving tokens.
 */
export abstract class BaseKeyProvider {
  /** Return the Fernet encryption key, or null to auto-generate. */
  abstract getEncryptionKey(): string | null;

  /** Return the HMAC master key, or null to auto-generate. */
  abstract getMasterKey(): string | null;
}

/**
 * Default provider: reads keys from environment variables.
 *
 * This preserves backwards compatibility with existing deployments.
 */
export class EnvKeyProvider extends BaseKeyProvider {
  getEncryptionKey(): string | null {
    return process.env.MASK_ENCRYPTION_KEY || null;
  }

  getMasterKey(): string | null {
    let key = process.env.MASK_MASTER_KEY || "";
    if (!key) {
      key = process.env.MASK_ENCRYPTION_KEY || "";
    }
    return key || null;
  }
}

/**
 * AWS KMS-backed key provider (stub — implement with AWS SDK).
 *
 * Usage:
 *
 *     setKeyProvider(new AwsKmsKeyProvider("alias/mask-encryption-key", "us-east-1"));
 *
 * Requires AWS SDK and valid AWS credentials.
 */
export class AwsKmsKeyProvider extends BaseKeyProvider {
  constructor(public keyId: string, public region: string = "us-east-1") {
    super();
  }

  getEncryptionKey(): string | null {
    throw new Error(
      "AwsKmsKeyProvider.getEncryptionKey() is a stub. " +
      "Implement with AWS SDK KMS GenerateDataKey / Decrypt to " +
      "retrieve the Fernet key from AWS KMS."
    );
  }

  getMasterKey(): string | null {
    throw new Error(
      "AwsKmsKeyProvider.getMasterKey() is a stub. " +
      "Implement with AWS SDK KMS to retrieve the HMAC master key."
    );
  }
}

/**
 * Azure Key Vault-backed key provider (stub — implement with Azure SDK).
 */
export class AzureKeyVaultProvider extends BaseKeyProvider {
  constructor(public vaultUrl: string) {
    super();
  }

  getEncryptionKey(): string | null {
    throw new Error(
      "AzureKeyVaultProvider.getEncryptionKey() is a stub. " +
      "Implement with @azure/keyvault-secrets SecretClient."
    );
  }

  getMasterKey(): string | null {
    throw new Error(
      "AzureKeyVaultProvider.getMasterKey() is a stub. " +
      "Implement with @azure/keyvault-secrets SecretClient."
    );
  }
}

/**
 * HashiCorp Vault-backed key provider (stub).
 */
export class HashiCorpVaultProvider extends BaseKeyProvider {
  constructor(public vaultAddr: string, public secretPath: string = "secret/data/mask") {
    super();
  }

  getEncryptionKey(): string | null {
    throw new Error(
      "HashiCorpVaultProvider.getEncryptionKey() is a stub."
    );
  }

  getMasterKey(): string | null {
    throw new Error(
      "HashiCorpVaultProvider.getMasterKey() is a stub."
    );
  }
}

// Singleton accessor
let providerInstance: BaseKeyProvider | null = null;

/**
 * Return the active key provider singleton.
 *
 * Defaults to EnvKeyProvider if no custom provider has been set.
 */
export function getKeyProvider(): BaseKeyProvider {
  if (providerInstance === null) {
    providerInstance = new EnvKeyProvider();
  }
  return providerInstance;
}

/**
 * Replace the active key provider singleton.
 */
export function setKeyProvider(provider: BaseKeyProvider): void {
  providerInstance = provider;
}

/**
 * Clear the singleton. Useful in tests.
 */
export function resetKeyProvider(): void {
  providerInstance = null;
}
