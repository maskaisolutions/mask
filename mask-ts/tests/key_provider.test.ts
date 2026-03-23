import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { 
  EnvKeyProvider, 
  AwsKmsKeyProvider, 
  AzureKeyVaultProvider, 
  HashiCorpVaultProvider, 
  getKeyProvider, 
  setKeyProvider, 
  resetKeyProvider 
} from '../src/core/key_provider';
import * as process from 'process';

describe('TestKeyProvider', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    resetKeyProvider();
    delete process.env.MASK_ENCRYPTION_KEY;
    delete process.env.MASK_MASTER_KEY;
  });

  afterEach(() => {
    Object.keys(process.env).forEach(key => delete process.env[key]);
    Object.assign(process.env, originalEnv);
    resetKeyProvider();
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

  test('test_env_provider_reads_from_environ', async () => {
    process.env.MASK_ENCRYPTION_KEY = "test-enc-key";
    process.env.MASK_MASTER_KEY = "test-master-key";
    
    const provider = new EnvKeyProvider();
    expect(await provider.getEncryptionKey()).toBe("test-enc-key");
    expect(await provider.getMasterKey()).toBe("test-master-key");
  });

  test('test_env_provider_falls_back_master_to_encryption', async () => {
    process.env.MASK_ENCRYPTION_KEY = "fallback-key";
    delete process.env.MASK_MASTER_KEY;
    
    const provider = new EnvKeyProvider();
    expect(await provider.getEncryptionKey()).toBe("fallback-key");
    expect(await provider.getMasterKey()).toBe("fallback-key");
  });

  test('test_kms_providers_functional', async () => {
    // Mock AWS
    const aws = new AwsKmsKeyProvider("alias/key");
    // @ts-ignore - mock internal
    aws._getSecretsClient = jest.fn().mockReturnValue({
      send: jest.fn().mockResolvedValue({ SecretString: "aws-key" })
    });
    expect(await aws.getEncryptionKey()).toBe("aws-key");

    // Mock Azure
    const azure = new AzureKeyVaultProvider("https://vault");
    // @ts-ignore
    azure._getClient = jest.fn().mockReturnValue({
      getSecret: jest.fn().mockResolvedValue({ value: "azure-key" })
    });
    expect(await azure.getEncryptionKey()).toBe("azure-key");

    // Mock HashiCorp
    const hashi = new HashiCorpVaultProvider("https://vault:8200");
    // We need to mock axios
    jest.mock('axios');
    const axios = require('axios');
    axios.get = jest.fn().mockResolvedValue({ 
      data: { data: { data: { value: "hashi-key" } } } 
    });
    expect(await hashi.getEncryptionKey()).toBe("hashi-key");
  });
});
