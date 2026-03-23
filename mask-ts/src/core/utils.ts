/**
 * Utility functions for the Mask SDK.
 *
 * Provides shared recursive data structures traversal algorithms used by the
 * various framework integration hooks (LangChain, LlamaIndex, ADK) to find
 * and intercept tokens/PII hidden deep inside nested dictionaries, lists,
 * and objects.
 */

import { detokenizeText, _decodeLenient } from './vault';
import { looksLikeToken } from './fpe';
import { getScanner } from './scanner';

const MAX_DEPTH = 100;

/**
 * Walk obj iteratively and detokenise all Mask tokens found.
 */
export async function deepDecode(obj: any): Promise<any> {
    return await _deepWalkIterative(obj, 'decode');
}

/**
 * Walk obj and tokenise PII using the Waterfall Scanner.
 */
export async function deepEncodePII(obj: any): Promise<any> {
    return await _deepWalkIterative(obj, 'encode');
}

/**
 * Internal iterative walker to prevent stack overflow.
 */
async function _deepWalkIterative(root: any, op: 'decode' | 'encode'): Promise<any> {
    if (root === null || root === undefined || typeof root !== 'object' && typeof root !== 'string') {
        return root;
    }

    const scanner = getScanner();
    
    // Process top-level string directly
    if (typeof root === 'string') {
        if (op === 'decode') return await detokenizeText(root);
        if (looksLikeToken(root)) return root;
        return await scanner.scanAndTokenize(root);
    }

    // Stack-based traversal to build a new object
    // Each item: { original, target, key, depth }
    // If target is null, it's the root.
    const result = Array.isArray(root) ? [] : {};
    const stack: { source: any, target: any, key: string | number | null, depth: number }[] = [
        { source: root, target: result, key: null, depth: 0 }
    ];

    while (stack.length > 0) {
        const { source, target, key, depth } = stack.pop()!;

        if (depth > MAX_DEPTH) continue;

        for (const [k, v] of Object.entries(source)) {
            if (v === null || v === undefined) {
                _setValue(target, key, k, v);
                continue;
            }

            if (typeof v === 'string') {
                let processed: string;
                if (op === 'decode') {
                    processed = await detokenizeText(v);
                } else {
                    processed = looksLikeToken(v) ? v : await scanner.scanAndTokenize(v);
                }
                _setValue(target, key, k, processed);
            } else if (typeof v === 'object') {
                const subTarget = Array.isArray(v) ? [] : {};
                _setValue(target, key, k, subTarget);
                stack.push({ source: v, target: subTarget, key: null, depth: depth + 1 });
            } else {
                _setValue(target, key, k, v);
            }
        }
    }

    return result;
}

function _setValue(parent: any, parentKey: string | number | null, key: string | number, value: any) {
    if (parentKey === null) {
        parent[key] = value;
    } else {
        // This helper isn't strictly needed given the current stack structure
        // but kept for clarity in complex tree grafts if needed.
        parent[key] = value;
    }
}
