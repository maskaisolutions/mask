import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { MaskClient } from '../src/client';

describe('Security Hardening Verification', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  test('verification: fail-shut security enforcement in production mode (default)', async () => {
    // Non-dev mode (default) — decryption failure should raise
    delete process.env.MASK_DEV_MODE;
    process.env.MASK_ENCRYPTION_KEY = "test-key";
    const { CryptoEngine } = require('../src/core/crypto');
    await CryptoEngine.getInstanceAsync();
    
    const client = new MaskClient();

    // @ts-ignore
    jest.spyOn(client.vault, 'retrieve').mockResolvedValue('cipher');
    // @ts-ignore
    jest.spyOn(client.crypto, 'decrypt').mockImplementation(() => {
      throw new Error("Decryption failed");
    });

    await expect(async () => await client.decode("MASK-123")).rejects.toThrow("Failed to decrypt token payload");
  });

  test('verification: fail-open in dev mode', async () => {
    process.env.MASK_DEV_MODE = 'true';
    const { CryptoEngine } = require('../src/core/crypto');
    await CryptoEngine.getInstanceAsync();
    
    const client = new MaskClient();
    const token = "MASK-123";

    // @ts-ignore
    jest.spyOn(client.vault, 'retrieve').mockResolvedValue('cipher');
    // @ts-ignore
    jest.spyOn(client.crypto, 'decrypt').mockImplementation(() => {
      throw new Error("Decryption failed");
    });

    const result = await client.decode(token);
    expect(result).toBe(token);
  });
});
