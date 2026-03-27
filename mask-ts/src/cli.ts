/**
 * CLI tool for Mask Privacy SDK (TypeScript).
 * Provides utilities for model management and environment pre-warming.
 */

import * as process from 'process';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { config } from './config';

async function cacheModels(languages: string[], cacheDir: string): Promise<void> {
    console.info(`[Mask CLI] Starting model pre-caching...`);
    console.info(`[Mask CLI] Languages: ${languages.join(', ')}`);
    console.info(`[Mask CLI] Cache Directory: ${cacheDir}`);

    if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true });
    }

    try {
        // Use dynamically imported @huggingface/transformers to avoid 
        // requiring it if the user just wants basic help.
        const { pipeline, env } = require('@huggingface/transformers');
        
        // Configure cache directory for Transformers.js
        env.cacheDir = cacheDir;
        env.localModelPath = cacheDir;

        const needsMultilingual = languages.some(l => l !== 'en');
        const modelName = config.MASK_NLP_MODEL || (needsMultilingual 
            ? 'Xenova/bert-base-multilingual-cased-ner-hrl' 
            : 'Xenova/distilbert-base-uncased-ner-simple');

        console.info(`[Mask CLI] Downloading Transformers model: ${modelName}`);
        
        // Trigger download by creating a pipeline
        await pipeline('token-classification', modelName);
        
        console.info(`[Mask CLI] Model pre-caching complete.`);
    } catch (e) {
        console.error(`[Mask CLI] Failed to cache models: ${e}`);
        process.exit(1);
    }
}

async function main() {
    const args = process.argv.slice(2);
    const command = args[0];

    if (command === 'cache-models') {
        const langIndex = args.indexOf('--languages');
        const cacheIndex = args.indexOf('--cache-dir');

        const languages = langIndex !== -1 ? args[langIndex + 1].split(',').map(l => l.trim().toLowerCase()) 
                                          : config.MASK_LANGUAGES.split(',');
        
        const cacheDir = cacheIndex !== -1 ? args[cacheIndex + 1] 
                                          : config.MASK_MODEL_CACHE_DIR;

        await cacheModels(languages, cacheDir);
    } else {
        console.info(`
Mask Privacy SDK CLI

Usage:
  npx ts-node src/cli.ts cache-models [options]

Options:
  --languages <langs>  Comma-separated list of languages (default: en)
  --cache-dir <path>   Path to cache directory
        `);
    }
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
