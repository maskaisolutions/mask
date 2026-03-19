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
            
            // In ioredis, connection error happens during operation or on 'error' event.
            // Our logic in RedisVault constructor doesn't await connection.
            // But we can check if it throws during a store operation.
            const vault = new RedisVault();
            // Mock redis.set to fail
            (vault as any)._redis = {
                set: jest.fn().mockRejectedValue(new Error("Connection refused") as never),
                get: jest.fn().mockRejectedValue(new Error("Connection refused") as never),
                quit: jest.fn().mockResolvedValue("OK" as never)
            };

            await expect(vault.store("t", "c", 60, "h")).rejects.toThrow(MaskVaultConnectionError);
        });

        test('test_dynamodb_atomic_write_raises_when_closed', async () => {
            process.env.MASK_FAIL_STRATEGY = "closed";
            
            const vault = new DynamoDBVault();
            // Mock client.send to fail for TransactWriteItemsCommand
            (vault as any)._client = {
                send: jest.fn().mockRejectedValue(new Error("Transaction cancelled") as never)
            };

            await expect(vault.store("tok123", "cipher", 600, "abc123")).rejects.toThrow(MaskVaultConnectionError);
        });
    });

    describe('TestFailStrategyOpen', () => {
        test('test_dynamodb_atomic_write_falls_back_when_open', async () => {
            process.env.MASK_FAIL_STRATEGY = "open";
            
            const vault = new DynamoDBVault();
            const sendSpy = jest.fn().mockImplementation((command: any) => {
                // Fail the transaction command
                if (command.constructor.name === 'TransactWriteCommand') {
                    return Promise.reject(new Error("Transaction cancelled"));
                }
                // Succeed for others (PutItemCommand if fallback used)
                return Promise.resolve({});
            });
            (vault as any)._client = { send: sendSpy };

            // Should NOT throw
            await vault.store("tok123", "cipher", 600, "abc123");
            
            // Check that it tried to fall back (multiple sends)
            expect(sendSpy.mock.calls.length).toBeGreaterThan(1);
        });
    });

    describe('TestFailStrategyDefault', () => {
        test('test_default_is_open', () => {
            delete process.env.MASK_FAIL_STRATEGY;
            expect(_getFailStrategy()).toBe("open");
        });
    });
});
