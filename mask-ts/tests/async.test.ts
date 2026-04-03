import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { aencode, adecode, resetVault, encode, decode } from '../src/core/vault';
import { resetMasterKey } from '../src/core/fpe';
import { looksLikeToken } from '../src/core/fpe_utils';
import { MaskClient } from '../src/client';
import * as process from 'process';

describe('TestAsyncWrappers', () => {
    beforeEach(() => {
        process.env.MASK_VAULT_TYPE = "memory";
        resetVault();
        resetMasterKey();
        process.env.MASK_MASTER_KEY = "test-async-key";
    });

    afterEach(() => {
        resetVault();
        resetMasterKey();
    });

    test('test_module_level_async_wrappers', async () => {
        const token = await aencode("test@async.com");
        expect(looksLikeToken(token)).toBe(true);
        expect(token).toMatch(/@async\.com$/);

        const plaintext = await adecode(token);
        expect(plaintext).toBe("test@async.com");
    });

    test('test_client_async_wrappers', async () => {
        const client = new MaskClient();
        
        // 1. Test encoding
        const token = await client.aencode("client@async.com");
        expect(looksLikeToken(token)).toBe(true);
        
        // 2. Test decoding
        const plaintext = await client.adecode(token);
        expect(plaintext).toBe("client@async.com");
        
        // 3. Test scanning
        const text = "Contact me at bob@example.com";
        const safeText = await client.ascanAndTokenize(text);
        expect(safeText).not.toContain("bob@example.com");
        expect(safeText).toContain("tkn-");
        expect(safeText).toMatch(/@example\.com$/);
    });
});
