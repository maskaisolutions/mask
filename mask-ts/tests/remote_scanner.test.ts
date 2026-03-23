import { describe, test, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { getScanner } from '../src/core/scanner';
import { RemoteScanner } from '../src/core/remote_scanner';

// Mock axios
jest.mock('axios');
const axios = require('axios');

describe('RemoteScanner', () => {
    let originalEnv: NodeJS.ProcessEnv;

    beforeEach(() => {
        originalEnv = { ...process.env };
        jest.clearAllMocks();
        // Reset singleton for testing
        (global as any).scannerInstance = null; 
        // Force require to reload or use the mock
    });

    afterEach(() => {
        process.env = originalEnv;
        // @ts-ignore
        require('../src/core/scanner').scannerInstance = null;
    });

    test('should call remote API and tokenize results', async () => {
        const scanner = new RemoteScanner('http://mock-presidio/analyze');
        
        axios.post.mockResolvedValue({
            data: [
                { start: 11, end: 19, entity_type: 'PERSON', score: 0.95 }
            ]
        });

        const text = "My name is John Doe and I live in NY.";
        // Note: scanAndTokenize calls _tier1Regex first (which handles emails/phones)
        // then _tier2Nlp (which we are mocking here).
        const result = await scanner.scanAndTokenize(text);

        expect(axios.post).toHaveBeenCalledWith('http://mock-presidio/analyze', {
            text: "My name is John Doe and I live in NY.",
            language: "en"
        }, expect.any(Object));

        // "John Doe" is at index 11, length 19. 
        expect(result).toContain('[TKN-');
        expect(result).not.toContain('John Doe');
    });

    test('should handle API errors gracefully', async () => {
        const scanner = new RemoteScanner();
        axios.post.mockRejectedValue(new Error("Network Error"));

        const text = "Hello John";
        const result = await scanner.scanAndTokenize(text);

        expect(result).toBe(text); // No change on error
    });

    test('should respect confidence threshold from remote response', async () => {
        const scanner = new RemoteScanner();
        axios.post.mockResolvedValue({
            data: [
                { start: 0, end: 4, entity_type: 'PERSON', score: 0.1 } // Low confidence
            ]
        });

        const text = "John is here";
        const result = await scanner.scanAndTokenize(text, { confidenceThreshold: 0.7 });

        expect(result).toBe(text); // Should not tokenize due to low confidence
    });
});
