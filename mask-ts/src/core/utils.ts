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
 * @param client - Optional MaskClient for tenant-isolated operation.
 */
export async function deepDecode(obj: any, client?: any): Promise<any> {
    return await _deepWalkIterative(obj, 'decode', client);
}

/**
 * Walk obj and tokenise PII using the Waterfall Scanner.
 * @param client - Optional MaskClient for tenant-isolated operation.
 */
export async function deepEncodePII(obj: any, client?: any): Promise<any> {
    return await _deepWalkIterative(obj, 'encode', client);
}

/**
 * Internal iterative walker to prevent stack overflow.
 */
async function _deepWalkIterative(root: any, op: 'decode' | 'encode', client?: any): Promise<any> {
    if (root === null || root === undefined || typeof root !== 'object' && typeof root !== 'string') {
        return root;
    }

    const scanner = client ? null : getScanner();
    
    // Process top-level string directly
    if (typeof root === 'string') {
        if (op === 'decode') return client ? await client.detokenizeText(root) : await detokenizeText(root);
        if (looksLikeToken(root)) return root;
        return client ? await client.scanAndTokenize(root) : await scanner!.scanAndTokenize(root);
    }

    // Two-pass approach:
    // Pass 1: Build the output structure iteratively, collecting string tasks
    // Pass 2: Process all strings concurrently, then graft results back

    const result = Array.isArray(root) ? [] : {};
    const stringTasks: { target: any, key: string | number, value: string }[] = [];

    const stack: { source: any, target: any, key: string | number | null, depth: number }[] = [
        { source: root, target: result, key: null, depth: 0 }
    ];

    while (stack.length > 0) {
        const { source, target, key, depth } = stack.pop()!;

        for (const [k, v] of Object.entries(source)) {
            if (v === null || v === undefined) {
                _setValue(target, key, k, v);
                continue;
            }

            if (typeof v === 'string') {
                // Placeholder — will be resolved in Pass 2
                _setValue(target, key, k, v);
                stringTasks.push({ target: key === null ? target : target, key: k, value: v });
            } else if (typeof v === 'object') {
                if (depth >= MAX_DEPTH) {
                    _setValue(target, key, k, v);
                } else {
                    const subTarget = Array.isArray(v) ? [] : {};
                    _setValue(target, key, k, subTarget);
                    stack.push({ source: v, target: subTarget, key: null, depth: depth + 1 });
                }
            } else {
                _setValue(target, key, k, v);
            }
        }
    }

    // Pass 2: Process all collected strings concurrently
    if (stringTasks.length > 0) {
        const processedValues = await Promise.all(
            stringTasks.map(async (task) => {
                if (op === 'decode') {
                    return client ? await client.detokenizeText(task.value) : await detokenizeText(task.value);
                } else {
                    if (looksLikeToken(task.value)) return task.value;
                    return client ? await client.scanAndTokenize(task.value) : await scanner!.scanAndTokenize(task.value);
                }
            })
        );

        // Graft results back into the structure
        for (let i = 0; i < stringTasks.length; i++) {
            stringTasks[i].target[stringTasks[i].key] = processedValues[i];
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
