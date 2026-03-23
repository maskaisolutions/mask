import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { DynamoDBVault, MemcachedVault, _hashPlaintext, resetVault } from '../src/core/vault';
import { resetKeyProvider } from '../src/core/key_provider';
import { MaskVaultConnectionError } from '../src/core/exceptions';
import * as process from 'process';

describe('TestVaultBackends', () => {
    let originalEnv: NodeJS.ProcessEnv;

    beforeEach(() => {
        originalEnv = { ...process.env };
        resetVault();
        resetKeyProvider();
    });

    afterEach(() => {
        Object.keys(process.env).forEach(key => delete process.env[key]);
        Object.assign(process.env, originalEnv);
        jest.restoreAllMocks();
    });

    describe('TestDynamoDBVault', () => {
        test('test_store_puts_item_with_ttl', async () => {
            process.env.MASK_DYNAMODB_TABLE = "test-table";
            process.env.MASK_DYNAMODB_REGION = "eu-west-1";
            
            const vault = new DynamoDBVault();
            const mockClient = {
                send: jest.fn<any>().mockResolvedValue({} as never)
            };
            (vault as any)._client = mockClient;

            const secretHash = _hashPlaintext("secret");
            const now = Math.floor(Date.now() / 1000);
            await vault.store("tok_1", "secret", 60, secretHash);

            expect(mockClient.send).toHaveBeenCalledTimes(1);
            const firstCall = mockClient.send.mock.calls[0][0] as any;
            const input = firstCall.input;
            
            expect(input.TransactItems[0].Put.Item.token).toBe("mask:tok_1");
            expect(input.TransactItems[0].Put.Item.ciphertext).toBe("secret");
            expect(input.TransactItems[0].Put.Item.ttl).toBeGreaterThanOrEqual(now + 60);

            expect(input.TransactItems[1].Put.Item.token).toBe(`mask-rev:${secretHash}`);
            expect(input.TransactItems[1].Put.Item.ciphertext).toBe("tok_1");
        });

        test('test_store_raises_on_transaction_failure', async () => {
            process.env.MASK_FAIL_STRATEGY = "open"; // Even in open mode, we expect failure for storage during encode
            const vault = new DynamoDBVault();
            const mockClient = {
                send: jest.fn<any>().mockRejectedValue(new Error("ProvisionedThroughputExceededException") as never)
            };
            (vault as any)._client = mockClient;

            await expect(vault.store("tok_fail", "data", 60, "hash")).rejects.toThrow(MaskVaultConnectionError);
        });

        test('test_retrieve_returns_val_and_handles_expiry', async () => {
            const vault = new DynamoDBVault();
            const now = Math.floor(Date.now() / 1000);
            
            const sendSpy = jest.fn<any>().mockImplementation(async (command: any) => {
                if (command.constructor.name === 'GetCommand') {
                    if (command.input.Key.token === "mask:tok_2") {
                        return {
                            Item: {
                                token: "mask:tok_2",
                                ciphertext: "safe",
                                ttl: now + 500
                            }
                        };
                    }
                }
                return {};
            });
            (vault as any)._client = { send: sendSpy };

            const res = await vault.retrieve("tok_2");
            expect(res).toBe("safe");

            const staleHash = _hashPlaintext("stale");
            sendSpy.mockResolvedValueOnce({
                Item: {
                    token: "mask:tok_expiration",
                    ciphertext: "stale",
                    ttl: now - 100,
                    ptr_hash: staleHash
                }
            } as never);

            sendSpy.mockResolvedValue({});

            const resExpired = await vault.retrieve("tok_expiration");
            expect(resExpired).toBeNull();
            
            const deleteCalls = sendSpy.mock.calls.filter((c: any) => c[0].constructor.name === 'DeleteCommand');
            expect(deleteCalls.length).toBeGreaterThanOrEqual(2);
        });
    });

    describe('TestMemcachedVault', () => {
        test('test_store_and_retrieve_and_delete', async () => {
            process.env.MASK_MEMCACHED_HOST = "localhost";
            process.env.MASK_MEMCACHED_PORT = "11211";
            
            const vault = new MemcachedVault();
            const mockClient = {
                set: jest.fn<any>().mockResolvedValue(true as never),
                get: jest.fn<any>().mockImplementation(async (key: string) => {
                    if (key === "mask:tok_A") return { value: Buffer.from("top_secret") };
                    if (key === "mask-hash:tok_A") return { value: Buffer.from(_hashPlaintext("top_secret")) };
                    return { value: null };
                }),
                delete: jest.fn<any>().mockResolvedValue(true as never)
            };
            (vault as any)._client = mockClient;

            const tsHash = _hashPlaintext("top_secret");
            await vault.store("tok_A", "top_secret", 300, tsHash);
            
            expect(mockClient.set).toHaveBeenCalledTimes(3);
            
            const retrieved = await vault.retrieve("tok_A");
            expect(retrieved).toBe("top_secret");
            
            await vault.delete("tok_A");
            expect(mockClient.delete).toHaveBeenCalledTimes(3);
        });
    });
});
