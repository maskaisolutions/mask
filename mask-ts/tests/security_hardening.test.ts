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

  test('verification: argon2id kdf enforcement', async () => {
    // Verify that the SDK refuses to initialize its CryptoEngine and fails shut
    // if the 'argon2' package is unavailable.
    
    // We must reset the module registry to ensure a fresh evaluation
    jest.resetModules();
    
    // Specifically mock 'argon2' to throw when required, simulating missing dependency
    jest.doMock('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });

    const { CryptoEngine } = require('../src/core/crypto');

    // Force a fresh reset of the singleton
    (CryptoEngine as any)._instance = null;
    process.env.MASK_ENCRYPTION_KEY = "test-key";

    await expect(async () => {
        await CryptoEngine.getInstanceAsync();
    }).rejects.toThrow(/argon2/);
    
    // Cleanup mock
    jest.dontMock('argon2');
  });

  test('verification: keyring key rotation (aes v2)', async () => {
    // Verify that the JSON MASK_KEYRING successfully rotates keys.
    // The CryptoEngine should encrypt using the "active" (last) key in the keyring,
    // and successfully decrypt both the active and historical ciphertexts without data loss.
    const { CryptoEngine } = require('../src/core/crypto');
    
    process.env.MASK_KEYRING = JSON.stringify({
      v1: "a".repeat(32),
      v2: "b".repeat(32)
    });
    
    CryptoEngine.reset();
    const crypto = await CryptoEngine.getInstanceAsync();
    
    const plaintext = "sensitive_data123";
    
    // 1. Encrypt uses the active (v2) key
    const ciphertextV2 = crypto.encrypt(plaintext);
    expect(ciphertextV2.startsWith("aes:v2:v2:")).toBe(true);
    
    // 2. Decrypting the current active key works
    const decryptedV2 = crypto.decrypt(ciphertextV2);
    expect(decryptedV2).toBe(plaintext);
    
    // 3. Simulate legacy ciphertext from the older v1 key
    // We temporarily set v1 as active just to generate a valid v1 ciphertext
    (crypto as any)._activeKeyId = "v1";
    const ciphertextV1 = crypto.encrypt(plaintext);
    expect(ciphertextV1.startsWith("aes:v2:v1:")).toBe(true);
    
    // Reset back to v2 as active
    (crypto as any)._activeKeyId = "v2";
    
    // 4. Decrypting the legacy (v1) ciphertext works seamlessly
    const decryptedV1 = crypto.decrypt(ciphertextV1);
    expect(decryptedV1).toBe(plaintext);
    
    CryptoEngine.reset();
  });

  test('verification: audit logger tamper evidence signature chain', () => {
    // Verify that _flushSync computes HMAC signatures correctly during a shutdown.
    // This ensures SOC 2 tamper-evidence guarantees hold through process termination.
    const { AuditLogger } = require('../src/telemetry/audit_logger');
    const cryptoNode = require('crypto');
    const fs = require('fs');

    const logger = new (AuditLogger as any)();
    
    const testEvt1 = { event_type: "tokenize", count: 1 };
    const testEvt2 = { event_type: "detokenize", count: 2 };
    
    // Push events to buffer
    logger._buffer.push(testEvt1);
    logger._buffer.push(testEvt2);
    
    // Spy on process.stdout.write to capture the synced output
    const stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    
    // We don't want to actually write to the filesystem in tests if we can just assert on stdout
    const fsSpy = jest.spyOn(fs, 'appendFileSync').mockImplementation(() => {});
    
    // Trigger sync flush
    logger._flushSync();
    
    expect(stdoutSpy).toHaveBeenCalledTimes(2);
    
    // Capture the JSON lines output
    const output1Str = stdoutSpy.mock.calls[0][0] as string;
    const output2Str = stdoutSpy.mock.calls[1][0] as string;
    
    const out1 = JSON.parse(output1Str.trim());
    const out2 = JSON.parse(output2Str.trim());
    
    // Verify signatures are present
    expect(out1.sig).toBeDefined();
    expect(out2.sig).toBeDefined();
    
    // Verify the chain connects
    expect(out2.prev_sig).toBe(out1.sig);
    
    // Verify HMAC correctness for out1
    const body1 = JSON.stringify(testEvt1);
    const expectedSigInput1 = Buffer.from(out1.prev_sig + body1, 'utf-8');
    const expectedSig1 = cryptoNode.createHmac('sha256', logger._signingKey).update(expectedSigInput1).digest('hex');
    expect(out1.sig).toBe(expectedSig1);
    
    stdoutSpy.mockRestore();
    fsSpy.mockRestore();
  });
});
