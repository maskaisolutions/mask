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

/**
 * Walk obj recursively and detokenise all Mask tokens found.
 *
 * This handles both 1:1 token matches and tokens embedded within larger
 * paragraphs (sub-string detokenization).
 */
export async function deepDecode(obj: any): Promise<any> {
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === 'string') {
        return await detokenizeText(obj);
    }

    if (Array.isArray(obj)) {
        return await Promise.all(obj.map(item => deepDecode(item)));
    }

    if (typeof obj === 'object') {
        // Plain object or class instance
        const newObj: any = Array.isArray(obj) ? [] : {};
        for (const [key, value] of Object.entries(obj)) {
            newObj[key] = await deepDecode(value);
        }
        return newObj;
    }

    return obj;
}

/**
 * Walk obj and tokenise PII using the Waterfall Scanner.
 */
export async function deepEncodePII(obj: any): Promise<any> {
    const _deepWalk = async (innerObj: any, op: 'decode' | 'encode'): Promise<any> => {
        if (innerObj === null || innerObj === undefined) return innerObj;

        if (typeof innerObj === 'string') {
            if (op === 'decode') {
                return looksLikeToken(innerObj) ? await _decodeLenient(innerObj) : innerObj;
            }
            if (op === 'encode') {
                if (looksLikeToken(innerObj)) return innerObj;
                return await getScanner().scanAndTokenize(innerObj);
            }
        }

        if (Array.isArray(innerObj)) {
            return await Promise.all(innerObj.map(item => _deepWalk(item, op)));
        }

        if (typeof innerObj === 'object') {
            const newObj: any = {};
            for (const [key, value] of Object.entries(innerObj)) {
                newObj[key] = await _deepWalk(value, op);
            }
            return newObj;
        }

        return innerObj;
    };

    return await _deepWalk(obj, 'encode');
}
