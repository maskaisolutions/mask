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

import { config } from '../config';

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
  abstract getEncryptionKey(): Promise<string | null> | string | null;

  /** Return the HMAC master key, or null to auto-generate. */
  abstract getMasterKey(): Promise<string | null> | string | null;

  /**
   * Return a JSON keyring string (e.g. from KMS / Secrets Manager), or null
   * to fall back to the MASK_KEYRING environment variable.
   *
   * Override in KMS-backed providers to source the full keyring from a
   * secure external store, removing the need for MASK_KEYRING in env vars.
   */
  getKeyring(): Promise<string | null> | string | null {
    return null;
  }
}

/**
 * Default provider: reads keys from environment variables.
 *
 * This preserves backwards compatibility with existing deployments.
 * If MASK_STRICT_PROD is set to 'true', this provider will throw an error
 * when keys are missing instead of returning null (fail-shut behavior).
 */
export class EnvKeyProvider extends BaseKeyProvider {
  async getEncryptionKey(): Promise<string | null> {
    const key = config.MASK_ENCRYPTION_KEY;
    if (!key && config.MASK_STRICT_PROD) {
      throw new Error(
        "MASK_STRICT_PROD is enabled but MASK_ENCRYPTION_KEY is not set. " +
        "The SDK is configured to fail-shut when keys are missing in production environments."
      );
    }
    return key;
  }

  async getMasterKey(): Promise<string | null> {
    let key = config.MASK_MASTER_KEY;
    return key || null;
  }

  /** Return MASK_KEYRING from environment (default behaviour). */
  async getKeyring(): Promise<string | null> {
    return config.MASK_KEYRING || null;
  }
}

/**
 * AWS KMS-backed key provider.
 *
 * Requires ``@aws-sdk/client-kms`` and ``@aws-sdk/client-secrets-manager``.
 */
export class AwsKmsKeyProvider extends BaseKeyProvider {
  private _secretsClient: any = null;
  private _kmsClient: any = null;

  constructor(public readonly keyId: string, public readonly region: string = "us-east-1") {
    super();
  }

  private async _getSecretsClient() {
    if (!this._secretsClient) {
      const { SecretsManagerClient } = require("@aws-sdk/client-secrets-manager");
      this._secretsClient = new SecretsManagerClient({ region: this.region });
    }
    return this._secretsClient;
  }

  private async _getKmsClient() {
    if (!this._kmsClient) {
      const { KMSClient } = require("@aws-sdk/client-kms");
      this._kmsClient = new KMSClient({ region: this.region });
    }
    return this._kmsClient;
  }

  /**
   * Envelope Encryption flow:
   * 1. If MASK_ENCRYPTED_KEY is set, use KMS to decrypt it (envelope encryption).
   * 2. Otherwise, fall back to fetching the raw key from Secrets Manager.
   * 3. If MASK_STRICT_PROD is set, envelope encryption is required.
   */
  async getEncryptionKey(): Promise<string | null> {
    // Envelope encryption path: decrypt a wrapped DEK via KMS
    const encryptedKey = config.MASK_ENCRYPTED_KEY;
    if (encryptedKey) {
      try {
        const { DecryptCommand } = require("@aws-sdk/client-kms");
        const kms = await this._getKmsClient();
        const response = await kms.send(new DecryptCommand({
          CiphertextBlob: Buffer.from(encryptedKey, 'base64'),
          KeyId: this.keyId,
        }));
        if (response.Plaintext) {
          return Buffer.from(response.Plaintext).toString('base64');
        }
        throw new Error("KMS DecryptCommand returned empty Plaintext.");
      } catch (e) {
        console.error("AWS KMS envelope decryption failed:", e);
        throw e;
      }
    }

    // In strict production mode or non-dev mode, envelope encryption is required
    // In strict production mode or non-dev mode, envelope encryption is required
    if (config.MASK_STRICT_PROD || !config.MASK_DEV_MODE) {
      throw new Error(
        'MASK_ENCRYPTED_KEY is not set. ' +
        'Envelope encryption via KMS is required in production modes. ' +
        'Set MASK_ENCRYPTED_KEY to a KMS-encrypted data encryption key.'
      );
    }

    // Fallback: raw key from Secrets Manager
    try {
      const { GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");
      const client = await this._getSecretsClient();
      const response = await client.send(new GetSecretValueCommand({ SecretId: this.keyId }));
      return response.SecretString || null;
    } catch (e) {
      console.error("AWS SecretsManager retrieval failed:", e);
      throw e;
    }
  }

  async getMasterKey(): Promise<string | null> {
    return await this.getEncryptionKey();
  }

  /**
   * Retrieve the JSON keyring from AWS Secrets Manager.
   *
   * If MASK_KEYRING_SECRET_ID is set, this provider fetches the full JSON
   * keyring document from Secrets Manager, enabling zero-downtime key
   * rotation without writing key material to environment variables.
   */
  async getKeyring(): Promise<string | null> {
    const secretId = process.env.MASK_KEYRING_SECRET_ID;
    if (!secretId) return null;
    try {
      const { GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
      const client = await this._getSecretsClient();
      const response = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
      const keyringStr = response.SecretString;
      if (!keyringStr) throw new Error('MASK_KEYRING_SECRET_ID returned an empty secret.');
      console.info(`Keyring loaded from AWS Secrets Manager (secret: ${secretId})`);
      return keyringStr;
    } catch (e) {
      console.error('Failed to retrieve keyring from AWS Secrets Manager:', e);
      throw e;
    }
  }
}

/**
 * Azure Key Vault-backed key provider.
 */
export class AzureKeyVaultProvider extends BaseKeyProvider {
  private _client: any = null;

  constructor(public readonly vaultUrl: string, public readonly secretName: string = "mask-encryption-key") {
    super();
  }

  private async _getClient() {
    if (!this._client) {
      const { SecretClient } = require("@azure/keyvault-secrets");
      const { DefaultAzureCredential } = require("@azure/identity");
      this._client = new SecretClient(this.vaultUrl, new DefaultAzureCredential());
    }
    return this._client;
  }

  async getEncryptionKey(): Promise<string | null> {
    try {
      const client = await this._getClient();
      const secret = await client.getSecret(this.secretName);
      return secret.value || null;
    } catch (e) {
      console.error("Azure Key Vault retrieval failed:", e);
      throw e;
    }
  }

  async getMasterKey(): Promise<string | null> {
    return await this.getEncryptionKey();
  }

  /**
   * Retrieve the JSON keyring from Azure Key Vault.
   * Looks for a secret named `<secretName>-keyring`.
   */
  async getKeyring(): Promise<string | null> {
    const keyringSecretName = this.secretName + '-keyring';
    try {
      const client = await this._getClient();
      const secret = await client.getSecret(keyringSecretName);
      if (secret.value) {
        console.info(`Keyring loaded from Azure Key Vault (secret: ${keyringSecretName})`);
        return secret.value;
      }
    } catch {
      // Secret may not exist; fall back to env
    }
    return null;
  }
}

/**
 * HashiCorp Vault-backed key provider.
 */
export class HashiCorpVaultProvider extends BaseKeyProvider {
  private _token: string | undefined;

  constructor(public readonly vaultAddr: string, public readonly secretPath: string = "secret/data/mask", token?: string) {
    super();
    this._token = token || config.VAULT_TOKEN || undefined;
  }

  async getEncryptionKey(): Promise<string | null> {
    try {
      const axios = require("axios");
      const url = `${this.vaultAddr}/v1/${this.secretPath}`;
      const response = await axios.get(url, {
        headers: { "X-Vault-Token": this._token }
      });
      const data = response.data?.data?.data || response.data?.data;
      return data?.encryption_key || data?.value || null;
    } catch (e) {
      console.error("HashiCorp Vault retrieval failed:", e);
      throw e;
    }
  }

  async getMasterKey(): Promise<string | null> {
    return await this.getEncryptionKey();
  }

  /**
   * Retrieve the JSON keyring from HashiCorp Vault.
   * Looks for a `keyring` key in the secret at `secretPath`.
   */
  async getKeyring(): Promise<string | null> {
    try {
      const axios = require('axios');
      const url = `${this.vaultAddr}/v1/${this.secretPath}`;
      const response = await axios.get(url, { headers: { 'X-Vault-Token': this._token } });
      const data = response.data?.data?.data || response.data?.data;
      const keyringStr = data?.keyring;
      if (keyringStr) {
        console.info(`Keyring loaded from HashiCorp Vault (path: ${this.secretPath})`);
        return keyringStr;
      }
    } catch (e) {
      console.error('HashiCorp Vault keyring retrieval failed:', e);
    }
    return null;
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
