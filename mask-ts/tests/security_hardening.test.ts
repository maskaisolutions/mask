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

  test('verification: fail-shut security enforcement in production mode', async () => {
    process.env.MASK_STRICT_PROD = 'true';
    const client = new MaskClient();

    // Mock retrieve to return ciphertext
    // @ts-ignore
    jest.spyOn(client.vault, 'retrieve').mockResolvedValue('cipher');
    // @ts-ignore
    jest.spyOn(client.crypto, 'decrypt').mockImplementation(() => {
      throw new Error("Decryption failed");
    });

    await expect(async () => await client.decode("MASK-123")).rejects.toThrow("Decryption failed");
  });

  test('verification: fail-open (legacy) in development mode', async () => {
    process.env.MASK_STRICT_PROD = 'false';
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
