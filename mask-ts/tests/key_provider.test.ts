import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { 
  EnvKeyProvider, 
  AwsKmsKeyProvider, 
  AzureKeyVaultProvider, 
  HashiCorpVaultProvider, 
  getKeyProvider, 
  setKeyProvider, 
  resetKeyProvider 
} from '../src/core/key_provider';

describe('TestKeyProvider', () => {
  beforeEach(() => {
    resetKeyProvider();
    delete process.env.MASK_ENCRYPTION_KEY;
    delete process.env.MASK_MASTER_KEY;
  });

  afterEach(() => {
    resetKeyProvider();
    delete process.env.MASK_ENCRYPTION_KEY;
    delete process.env.MASK_MASTER_KEY;
  });

  test('test_default_is_env_provider', () => {
    const provider = getKeyProvider();
    expect(provider).toBeInstanceOf(EnvKeyProvider);
  });

  test('test_set_custom_provider', () => {
    class DummyProvider extends EnvKeyProvider {}
    const dummy = new DummyProvider();
    setKeyProvider(dummy);
    expect(getKeyProvider()).toBe(dummy);
  });

  test('test_env_provider_reads_from_environ', () => {
    process.env.MASK_ENCRYPTION_KEY = "test-enc-key";
    process.env.MASK_MASTER_KEY = "test-master-key";
    
    const provider = new EnvKeyProvider();
    expect(provider.getEncryptionKey()).toBe("test-enc-key");
    expect(provider.getMasterKey()).toBe("test-master-key");
  });

  test('test_env_provider_falls_back_master_to_encryption', () => {
    process.env.MASK_ENCRYPTION_KEY = "fallback-key";
    delete process.env.MASK_MASTER_KEY;
    
    const provider = new EnvKeyProvider();
    expect(provider.getEncryptionKey()).toBe("fallback-key");
    expect(provider.getMasterKey()).toBe("fallback-key");
  });

  test('test_stub_providers_raise_not_implemented', () => {
    const aws = new AwsKmsKeyProvider("alias/key");
    expect(() => aws.getEncryptionKey()).toThrow();
    expect(() => aws.getMasterKey()).toThrow();
        
    const azure = new AzureKeyVaultProvider("https://vault");
    expect(() => azure.getEncryptionKey()).toThrow();
    expect(() => azure.getMasterKey()).toThrow();
        
    const hashi = new HashiCorpVaultProvider("https://vault:8200");
    expect(() => hashi.getEncryptionKey()).toThrow();
    expect(() => hashi.getMasterKey()).toThrow();
  });
});
