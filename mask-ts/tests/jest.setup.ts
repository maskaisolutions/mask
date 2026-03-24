// Mock @huggingface/transformers to avoid environment-specific tensor errors
jest.mock('@huggingface/transformers', () => ({
  pipeline: jest.fn().mockResolvedValue(async (text: string) => {
    // Return a simple mock result for known test strings
    if (text.includes("John Doe") || text.includes("admin@hospital.com") || text.includes("llamaindex@mask.ai") || text.includes("bob@example.com")) {
      return [
        { entity: 'B-PER', score: 0.99, index: 1, word: 'John', start: text.indexOf('John'), end: text.indexOf('John') + 4 },
        { entity: 'I-PER', score: 0.99, index: 2, word: 'Doe', start: text.indexOf('Doe'), end: text.indexOf('Doe') + 3 },
        { entity: 'B-EMAIL', score: 0.99, index: 3, word: 'admin@hospital.com', start: text.indexOf('admin@hospital.com'), end: text.indexOf('admin@hospital.com') + 18 },
        { entity: 'B-EMAIL', score: 0.99, index: 4, word: 'llamaindex@mask.ai', start: text.indexOf('llamaindex@mask.ai'), end: text.indexOf('llamaindex@mask.ai') + 18 },
        { entity: 'B-EMAIL', score: 0.99, index: 5, word: 'bob@example.com', start: text.indexOf('bob@example.com'), end: text.indexOf('bob@example.com') + 15 },
      ].filter(r => r.start !== -1);
    }
    return [];
  })
}), { virtual: true });

import * as crypto from 'crypto';
import { getAuditLogger } from '../src/telemetry/audit_logger';


process.env.MASK_DEV_MODE = "true";
if (!process.env.MASK_ENCRYPTION_KEY) {
  // Generate a unique-per-test-run key (AES-256-GCM uses SHA-256 derivation)
  process.env.MASK_ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');
}

afterEach(async () => {
    await getAuditLogger().stop();
});
