/**
 * LangChain integration for Mask Privacy SDK.
 *
 * Provides:
 *   - MaskCallbackHandler — plugs into LangChain's callback system.
 *   - MaskToolWrapper     — wraps any callable for auto-encode/decode.
 *   - secureTool         — drop-in decorator/wrapper for tools.
 */

import { deepDecode, deepEncodePII } from '../core/utils';

/**
 * Tool wrapper (explicit, works with any callable)
 */
export class MaskToolWrapper {
  private _func: Function;

  constructor(func: Function) {
    this._func = func;
  }

  async run(...args: any[]): Promise<any> {
    const decodedArgs = await Promise.all(args.map(a => deepDecode(a)));
    const result = await this._func(...decodedArgs);
    if (typeof result === 'string' || typeof result === 'object') {
        return await deepEncodePII(result);
    }
    return result;
  }
}

/**
 * secureTool wrapper/decorator.
 *
 * Usage:
 *    const myTool = secureTool((arg1, arg2) => { ... });
 */
export function secureTool(func: Function, options: { name?: string, description?: string } = {}): any {
  const wrapper = async (...args: any[]) => {
    const decodedArgs = await Promise.all(args.map(a => deepDecode(a)));
    const result = await func(...decodedArgs);
    if (typeof result === 'string' || typeof result === 'object') {
        return await deepEncodePII(result);
    }
    return result;
  };

  if (options.name) {
    Object.defineProperty(wrapper, 'name', { value: options.name, configurable: true });
  }
  if (options.description) {
    (wrapper as any).description = options.description;
  }

  return wrapper;
}

/**
 * LangChain callback handler.
 */
export async function getMaskCallbackHandler() {
    try {
        const { StructuredTool } = require('@langchain/core/tools');
        const { BaseCallbackHandler } = require('@langchain/core/callbacks/base');

        return class MaskCallbackHandler extends BaseCallbackHandler {
            name = "MaskPrivacyHandler";

            async handleToolStart(tool: any, input: string, runId: string, parentRunId?: string, tags?: string[], metadata?: Record<string, any>, inputs?: Record<string, any>): Promise<void> {
                if (inputs) {
                    const decoded = await deepDecode(inputs);
                    Object.assign(inputs, decoded);
                }
            }

            async handleToolEnd(output: string, runId: string, parentRunId?: string): Promise<void> {
                // Logging/audit only
            }
        };
    } catch (e) {
        return class MaskCallbackHandler {
            constructor() {
                throw new Error("@langchain/core is required for LangChain integration.");
            }
        };
    }
}
