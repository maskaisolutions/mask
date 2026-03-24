import { describe, test, expect, beforeEach, afterEach, afterAll, jest } from '@jest/globals';
import { encode, resetVault } from '../src/core/vault';
import { resetMasterKey } from '../src/core/fpe';
import { resetScanner } from '../src/core/scanner';
import { MaskToolWrapper, secureTool, getMaskCallbackHandler } from '../src/integrations/langchain_hooks';
import { getAuditLogger } from '../src/telemetry/audit_logger';
import * as process from 'process';

jest.setTimeout(10000);

describe('TestLangchainHooks', () => {
    beforeEach(() => {
        process.env.MASK_VAULT_TYPE = "memory";
        process.env.MASK_SCANNER_TYPE = "regex";
        resetVault();
        resetScanner();
        resetMasterKey();
        process.env.MASK_MASTER_KEY = "test-langchain-key";
    });

    afterEach(() => {
        resetVault();
        resetMasterKey();
    });

    afterAll(async () => {
        await getAuditLogger().stop();
    });

    describe('TestLangchainMaskToolWrapper', () => {
        test('test_wrapper_detokenizes_inputs_and_tokenizes_outputs', async () => {
            const token = await encode("user@example.com");

            const mockTool = jest.fn<any>().mockImplementation(async (email: string, subject: string) => {
                expect(email).toBe("user@example.com");
                expect(subject).toBe("Welcome");
                return {"target": email, "subject": subject};
            });

            const secure = new MaskToolWrapper(mockTool);
            const result = await secure.run(token, "Welcome");

            expect(result.target).not.toBe("user@example.com");
            expect(result.target).toMatch(/@email\.com$/);
        });
    });

    describe('TestLangchainMaskCallbackHandler', () => {
        test('test_on_tool_start_does_not_mutate_inputs', async () => {
             // Mock BaseCallbackHandler since we don't want to install @langchain/core in this environment if not present
            const MockHandlerClass = await getMaskCallbackHandler();
            const handler = new MockHandlerClass();

            const token1 = await encode("alice@corp.io");
            const token2 = await encode("bob@corp.io");

            const inputsDict = {
                "primary": token1,
                "cc": [token2, "charlie@corp.io"],
            };

            if ((handler as any).handleToolStart) {
                await (handler as any).handleToolStart(
                    {"name": "send_email"},
                    "...",
                    "run-id",
                    undefined,
                    [],
                    {},
                    inputsDict
                );

                // Inputs should NOT be mutated — they should remain tokenized
                expect(inputsDict.primary).toBe(token1);
                expect(inputsDict.cc[0]).toBe(token2);
                expect(inputsDict.cc[1]).toBe("charlie@corp.io");
            }
        });
    });

    describe('TestLangchainSecureTool', () => {
        test('test_secure_tool_decorator_detokenizes_and_retokenizes', async () => {
            const token = await encode("dev@mask.ai");

            const sendEmail = secureTool(async (email: string, body: string) => {
                expect(email).toBe("dev@mask.ai");
                return `Sent to ${email}`;
            });

            const result = await sendEmail(token, "Hello");
            expect(result).not.toContain("dev@mask.ai");
            expect(result).toContain("@email.com");
        });

        test('test_secure_tool_preserves_non_pii', async () => {
            const greet = secureTool(async (name: string) => {
                return `Hello, ${name}!`;
            });

            const result = await greet("World");
            expect(result).toBe("Hello, World!");
        });

        test('test_secure_tool_with_custom_name', () => {
            const lookup = secureTool(async (userId: string) => {
                return {"id": userId};
            }, { name: "custom_lookup" });

            expect(lookup.name).toBe("custom_lookup");
        });
    });
});
