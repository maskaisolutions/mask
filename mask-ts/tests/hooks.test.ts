import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { encode, resetVault } from '../src/core/vault';
import { resetMasterKey } from '../src/core/fpe';
import { decryptBeforeTool, encryptAfterTool } from '../src/integrations/adk_hooks';
import { deepDecode, deepEncodePII } from '../src/core/utils';
import { looksLikeToken } from '../src/core/fpe_utils';
import * as process from 'process';

// Minimal stubs matching ADK protocol
class FakeTool {
    name = "test_tool";
}

class FakeCtx {
    agentName = "test_agent";
}

describe('TestHooks', () => {
    beforeEach(() => {
        process.env.MASK_VAULT_TYPE = "memory";
        resetVault();
        resetMasterKey();
        process.env.MASK_MASTER_KEY = "test-hooks-key";
    });

    afterEach(() => {
        resetVault();
        resetMasterKey();
    });

    describe('TestDeepDecode', () => {
        test('test_flat_dict', async () => {
            const token = await encode("alice@corp.io");
            const result = await deepDecode({"email": token, "msg": "hi"});
            expect(result.email).toBe("alice@corp.io");
            expect(result.msg).toBe("hi");
        });

        test('test_nested_dict', async () => {
            const token = await encode("bob@bank.com");
            const data = {"user": {"contact": {"email": token}}};
            const result = await deepDecode(data);
            expect(result.user.contact.email).toBe("bob@bank.com");
        });

        test('test_list_values', async () => {
            const t1 = await encode("a@b.com");
            const t2 = await encode("c@d.com");
            const result = await deepDecode({"recipients": [t1, t2]});
            expect(result.recipients).toEqual(["a@b.com", "c@d.com"]);
        });

        test('test_non_token_strings_unchanged', async () => {
            const result = await deepDecode({"name": "Alice", "age": 30});
            expect(result).toEqual({"name": "Alice", "age": 30});
        });
    });

    describe('TestDeepEncodeEmails', () => {
        test('test_encodes_raw_email', async () => {
            const result = await deepEncodePII({"email": "test@example.com"});
            expect(looksLikeToken(result.email)).toBe(true);
            expect(result.email).toMatch(/@example\.com$/);
        });

        test('test_does_not_double_encode_token', async () => {
            const token = await encode("original@test.com");
            const result = await deepEncodePII({"email": token});
            expect(result.email).toBe(token);
        });
    });

    describe('TestDecryptBeforeTool', () => {
        test('test_mutates_args_in_place', async () => {
            const token = await encode("admin@secure.io");
            const args = {"email": token, "action": "send"};
            await decryptBeforeTool(new FakeTool(), args, new FakeCtx());
            expect(args.email).toBe("admin@secure.io");
            expect(args.action).toBe("send");
        });
    });

    describe('TestEncryptAfterTool', () => {
        test('test_encodes_leaked_emails_in_args', async () => {
            const args = {"email": "leaked@plain.com"};
            await encryptAfterTool(new FakeTool() as any, args, new FakeCtx() as any, {});
            expect(looksLikeToken(args.email)).toBe(true);
        });

        test('test_encodes_leaked_emails_in_string_response', async () => {
            const args = "Contact us at support@example.com for help.";
            const result = await deepEncodePII(args);
            expect(typeof result).toBe('string');
            expect(result).toContain("@example.com");
            expect(result).not.toContain("support@example.com");
        });

        test('test_encodes_leaked_emails_but_skips_tokens_in_nested_dict', async () => {
            const token = await encode("admin@secure.io");
            const args = {"response": {"leaked": "bad@plain.com", "safe": token}};
            const result = await deepEncodePII(args);
            
            expect(looksLikeToken(result.response.leaked)).toBe(true);
            expect(result.response.safe).toBe(token);
        });
    });
});
