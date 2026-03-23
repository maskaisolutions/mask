import { encode, getVault, resetVault } from '../src/core/vault';
import { BucketManager } from '../src/core/search';
import { getCryptoEngine } from '../src/core/crypto';
import { _hashPlaintext } from '../src/core/vault';

describe('Search Bucketing Integration', () => {
  beforeEach(() => {
    process.env.MASK_VAULT_TYPE = 'memory';
    process.env.MASK_MASTER_KEY = 'test_master_key_for_search_bucketing';
    resetVault();
  });

  afterEach(() => {
    resetVault();
  });

  it('should store multiple indices for a date with buckets', async () => {
    const dateVal = "2023-10-25";
    const token = await encode(dateVal, { searchBuckets: ['month', 'year'] });

    const vault = getVault();
    const crypto = await getCryptoEngine();
    const indexSecret = await crypto.getIndexSecret();

    // 1. Exact match
    const primaryHash = _hashPlaintext(dateVal, indexSecret);
    expect(await vault.getTokenByPlaintextHash(primaryHash)).toBe(token);

    // 2. Month bucket
    const monthVal = "date:m:2023-10";
    const monthHash = await BucketManager.getBucketIndex(monthVal);
    expect(await vault.getTokenByPlaintextHash(monthHash)).toBe(token);

    // 3. Year bucket
    const yearVal = "date:y:2023";
    const yearHash = await BucketManager.getBucketIndex(yearVal);
    expect(await vault.getTokenByPlaintextHash(yearHash)).toBe(token);
  });

  it('should store indices for numeric buckets', async () => {
    const salary = "125000";
    const token = await encode(salary, { searchBuckets: ['numeric'], searchBucketSize: 1000 });

    const vault = getVault();
    
    // Bucket for 125000 with size 1000 is "num:1000:125000"
    const bucketVal = "num:1000:125000";
    const bucketHash = await BucketManager.getBucketIndex(bucketVal);
    expect(await vault.getTokenByPlaintextHash(bucketHash)).toBe(token);
  });

  it('should maintain deduplication when buckets are used', async () => {
    const val = "duplicate_test";
    const token1 = await encode(val, { searchBuckets: ['month'] });
    const token2 = await encode(val, { searchBuckets: ['month'] });

    expect(token1).toBe(token2);
  });
});
