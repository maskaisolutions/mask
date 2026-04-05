/**
 * Mask Privacy SDK
 * Just-In-Time Privacy Middleware for AI Agents.
 *
 * Provides format-preserving encryption, local/distributed vaulting,
 * and framework-agnostic tool interception hooks.
 */

export const VERSION = "3.5.0";

export {
    getVault,
    encode,
    decode,
    aencode,
    adecode,
    detokenizeText,
    adetokenizeText,
} from './core/vault';

export {
    generateFPEToken,
    looksLikeToken,
    resetMasterKey,
} from './core/fpe';

export {
    getScanner,
    BaseScanner,
    PresidioScanner,
} from './core/scanner';

export {
    LocalTransformersScanner,
} from './core/transformers_scanner';

export {
    MaskError,
    MaskVaultConnectionError,
    MaskDecryptionError,
    MaskNLPTimeout,
    MaskSecurityError,
} from './core/exceptions';

import { getScanner } from './core/scanner';

/**
 * Detect PII entities in text and return a list of objects with metadata.
 */
export async function detectEntitiesWithConfidence(
    text: string,
    options: {
        pipeline?: string[];
        confidenceThreshold?: number;
        context?: string | null;
        aggressive?: boolean;
    } = {}
): Promise<any[]> {
    const scanner = getScanner();
    return await scanner.scanAndReturnEntities(text, options);
}

/**
 * Async variant of getScanner().scanAndTokenize().
 */
export async function ascanAndTokenize(
    text: string,
    options: {
        pipeline?: string[];
        confidenceThreshold?: number;
        context?: string | null;
        aggressive?: boolean;
    } = {}
): Promise<string> {
    const scanner = getScanner();
    return await scanner.scanAndTokenize(text, options);
}

export { MaskClient } from './client';

// DLP sub-package (Multilingual detection, 50+ types)
export {
    LanguageContextResolver,
    DLPPatternRegistry,
    SensitiveCategory,
    DLPValidationEngine,
    DLPConfidenceScorer,
} from './core/dlp';

/**
 * Drop-in decorator for LangChain tools with automatic PII protection.
 */
export function secureTool(...args: any[]): any {
    /**
     * In TS, we'll implement this inside the integrations folder soon.
     * For now, this is a placeholder that will point to the actual implementation.
     */
    const { secureTool: _secureTool } = require('./integrations/langchain_hooks');
    return _secureTool(...args);
}

