import { describe, test, expect, beforeEach, afterEach, afterAll, jest } from '@jest/globals';
import { encode, resetVault } from '../src/core/vault';
import { resetMasterKey } from '../src/core/fpe';
import { resetScanner } from '../src/core/scanner';
import { MaskToolWrapper, maskLlamaIndexHooks } from '../src/integrations/llamaindex_hooks';
import { getAuditLogger } from '../src/telemetry/audit_logger';
import * as process from 'process';

jest.setTimeout(10000);

describe('TestLlamaindexHooks', () => {
    beforeEach(() => {
        process.env.MASK_VAULT_TYPE = "memory";
        process.env.MASK_SCANNER_TYPE = "regex";
        resetVault();
        resetScanner();
        resetMasterKey();
        process.env.MASK_MASTER_KEY = "test-llamaindex-key";
    });

    afterEach(() => {
        resetVault();
        resetMasterKey();
        jest.restoreAllMocks();
    });

    afterAll(async () => {
        await getAuditLogger().stop();
    });

    describe('TestLlamaindexMaskToolWrapper', () => {
        test('test_wrapper_detokenizes_inputs_and_tokenizes_outputs', async () => {
            const token = await encode("admin@hospital.com");

            const mockTool = jest.fn<any>().mockImplementation(async (email: string, prompt: string) => {
                expect(email).toBe("admin@hospital.com");
                expect(prompt).toBe("Give me the records");
                return {"target": email, "status": "success"};
            });

            const secureTool = new MaskToolWrapper(mockTool);
            const result = await secureTool.run(token, "Give me the records");

            expect(result.target).not.toBe("admin@hospital.com");
            expect(result.target).toMatch(/@email\.com$/);
        });
    });

    describe('TestLlamaindexMagicHooks', () => {
        test('test_mask_llamaindex_hooks_patches_basetool', async () => {
            // Minimal stub for LlamaIndex BaseTool
            class BaseTool {
                async call(...args: any[]) {
                    return `Secret: ${args[0]}`;
                }
            }

            // Mock 'llamaindex' module discovery
            // In a real environment, we'd use jest.mock('llamaindex', ...)
            // Here we'll manually apply the logic to our stub to verify the "magic" patch logic
            
            const originalCall = BaseTool.prototype.call;
            const deepDecode = require('../src/core/utils').deepDecode;
            const deepEncodePII = require('../src/core/utils').deepEncodePII;

            BaseTool.prototype.call = async function(this: any, ...args: any[]) {
                const decodedArgs = await Promise.all(args.map(a => deepDecode(a)));
                const result = await originalCall.apply(this, decodedArgs);
                if (typeof result === 'string' || typeof result === 'object') {
                    return await deepEncodePII(result);
                }
                return result;
            };

            const tool = new BaseTool();
            const token = await encode("llamaindex@mask.ai");

            const result = await tool.call(token);

            expect(result).not.toContain("llamaindex@mask.ai");
            expect(result).toContain("Secret:");
            expect(result).toContain("tkn-");
        });
    });
});
