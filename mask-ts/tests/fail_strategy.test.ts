import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { RedisVault, DynamoDBVault, _getFailStrategy } from '../src/core/vault';
import { MaskVaultConnectionError } from '../src/core/exceptions';
import * as process from 'process';

// Mock values
const DUMMY_URL = "redis://localhost:59999/0";

describe('TestFailStrategy', () => {
    let originalEnv: NodeJS.ProcessEnv;

    beforeEach(() => {
        originalEnv = { ...process.env };
    });

    afterEach(() => {
        Object.keys(process.env).forEach(key => delete process.env[key]);
        Object.assign(process.env, originalEnv);
        jest.restoreAllMocks();
    });

    describe('TestFailStrategyClosed', () => {
        test('test_redis_vault_raises_on_connection_failure', async () => {
            process.env.MASK_FAIL_STRATEGY = "closed";
            process.env.MASK_REDIS_URL = DUMMY_URL;
            process.env.MASK_VAULT_TYPE = "redis";
            
            const vault = new RedisVault();
            const mockRedis = {
                pipeline: jest.fn<any>().mockReturnValue({
                    set: jest.fn<any>().mockReturnThis(),
                    exec: jest.fn<any>().mockRejectedValue(new Error("Connection refused"))
                }),
                quit: jest.fn<any>().mockResolvedValue("OK")
            };
            (vault as any)._client = mockRedis;

            await expect(vault.store("t", "c", 60, "h")).rejects.toThrow(MaskVaultConnectionError);
        });

        test('test_dynamodb_atomic_write_raises_when_closed', async () => {
            process.env.MASK_FAIL_STRATEGY = "closed";
            
            const vault = new DynamoDBVault();
            (vault as any)._client = {
                send: jest.fn<any>().mockRejectedValue(new Error("Transaction cancelled"))
            };

            await expect(vault.store("tok123", "cipher", 600, "abc123")).rejects.toThrow(MaskVaultConnectionError);
        });
    });

    describe('TestFailStrategyOpen', () => {
        test('test_dynamodb_atomic_write_raises_even_when_open', async () => {
            // Updated behavior: DynamoDB failures always raise to prevent silent data loss
            process.env.MASK_FAIL_STRATEGY = "open";
            
            const vault = new DynamoDBVault();
            (vault as any)._client = {
                send: jest.fn<any>().mockRejectedValue(new Error("Transaction cancelled"))
            };

            // Should THROW because we don't want to lose the primary record if the atomic write fails
            await expect(vault.store("tok123", "cipher", 600, "abc123")).rejects.toThrow(MaskVaultConnectionError);
        });

        test('test_redis_vault_returns_null_when_open', async () => {
           process.env.MASK_FAIL_STRATEGY = "open";
           const vault = new RedisVault();
           const mockRedis = {
                pipeline: jest.fn<any>().mockReturnValue({
                    set: jest.fn<any>().mockReturnThis(),
                    exec: jest.fn<any>().mockRejectedValue(new Error("Connection failed"))
                })
           };
           (vault as any)._client = mockRedis;

           // Calling store should resolve (silent failure)
           await expect(vault.store("t", "c", 60, "h")).resolves.toBeUndefined();
        });
    });

    describe('TestFailStrategyDefault', () => {
        test('test_default_is_open', () => {
            delete process.env.MASK_FAIL_STRATEGY;
            expect(_getFailStrategy()).toBe("open");
        });
    });
});
