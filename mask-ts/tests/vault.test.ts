import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { MemoryVault, encode, decode, getVault, resetVault, _decodeLenient, DecodeError } from '../src/core/vault';
import { resetMasterKey } from '../src/core/fpe';

describe('TestMemoryVault', () => {
  let vault: MemoryVault;

  beforeEach(() => {
    vault = new MemoryVault();
  });

  test('test_store_and_retrieve', async () => {
    await vault.store("tok1", "hello", 60);
    expect(await vault.retrieve("tok1")).toBe("hello");
  });

  test('test_missing_key_returns_none', async () => {
    expect(await vault.retrieve("nope")).toBe(null);
  });

  test('test_expired_key_returns_none', async () => {
    await vault.store("tok2", "data", 0);
    await new Promise(r => setTimeout(r, 50));
    expect(await vault.retrieve("tok2")).toBe(null);
  });

  test('test_delete', async () => {
    await vault.store("tok3", "val", 60);
    await vault.delete("tok3");
    expect(await vault.retrieve("tok3")).toBe(null);
  });
});

describe('TestEncodeDecodePublicAPI', () => {
  beforeEach(() => {
    resetVault();
    resetMasterKey();
    process.env.MASK_VAULT_TYPE = "memory";
    process.env.MASK_MASTER_KEY = "test-vault-key";
  });

  afterEach(() => {
    resetVault();
    resetMasterKey();
  });

  test('test_roundtrip_email', async () => {
    const token = await encode("user@example.com");
    expect(token.endsWith("@email.com")).toBe(true);
    expect(await decode(token)).toBe("user@example.com");
  });

  test('test_roundtrip_opaque', async () => {
    const token = await encode("some secret value");
    expect(token.startsWith("[TKN-")).toBe(true);
    expect(await decode(token)).toBe("some secret value");
  });

  test('test_decode_unknown_token_raises', async () => {
    await expect(decode("garbage")).rejects.toThrow(DecodeError);
  });

  test('test_lenient_helper_unknown_token_returns_itself', async () => {
    expect(await _decodeLenient("garbage")).toBe("garbage");
  });

  test('test_custom_ttl', async () => {
    const token = await encode("x@y.com", { ttl: 1 });
    expect(await decode(token)).toBe("x@y.com");
    await new Promise(r => setTimeout(r, 1100));
    await expect(decode(token)).rejects.toThrow(DecodeError);
  });

  test('test_lenient_helper_respects_custom_ttl', async () => {
    const token = await encode("x@y.com", { ttl: 1 });
    expect(await _decodeLenient(token)).toBe("x@y.com");
    await new Promise(r => setTimeout(r, 1100));
    expect(await _decodeLenient(token)).toBe(token);
  });

  test('test_deduplication', async () => {
    const token1 = await encode("dedup@example.com");
    const token2 = await encode("dedup@example.com");
    expect(token1).toBe(token2);

    const token3 = await encode("other@example.com");
    expect(token1).not.toBe(token3);
  });

  test('test_encode_skips_existing_tokens', async () => {
    const token1 = await encode("alice@example.com");
    const token2 = await encode(token1);
    expect(token1).toBe(token2);
  });

  test('test_dedup_ignores_whitespace', async () => {
    const token1 = await encode(" bob@example.com ");
    const token2 = await encode("bob@example.com");
    expect(token1).toBe(token2);
  });
});
