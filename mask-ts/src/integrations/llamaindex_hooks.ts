/**
 * LlamaIndex integration for Mask Privacy SDK.
 *
 * Provides a MaskToolWrapper and a "magic" hook for LlamaIndex's tool
 * pipelines to automatically tokenise/detokenise data.
 */

import { deepDecode, deepEncodePII } from '../core/utils';

/**
 * Tool Wrapper — works with any callable.
 */
export class MaskToolWrapper {
  private _func: Function;
  public name: string;
  public description: string;

  constructor(func: Function) {
    this._func = func;
    this.name = (func as any).name || "mask_wrapped";
    this.description = (func as any).description || "";
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
 * LlamaIndex callback handler.
 */
export async function getMaskCallbackHandler() {
    try {
        const { BaseCallbackHandler } = require("llamaindex");
        // LlamaIndex TS callback API might differ, providing a stub-like implementation
        // that follows the expected pattern if it exists.
        return class MaskCallbackHandler extends BaseCallbackHandler {
            // Implementation depends on llamaindex TS version
        };
    } catch (e) {
        return class MaskCallbackHandler {
            constructor() {
                throw new Error("llamaindex is required for LlamaIndex integration.");
            }
        };
    }
}

/**
 * "Magic" hook for LlamaIndex PII protection via prototype overriding.
 */
export function maskLlamaIndexHooks(): void {
  try {
    const { BaseTool } = require("llamaindex");
    if (!BaseTool || !BaseTool.prototype) return;

    const originalCall = BaseTool.prototype.call;
    if (!originalCall) return;

    BaseTool.prototype.call = async function(this: any, ...args: any[]) {
      // 1. Detokenize inputs
      const decodedArgs = await Promise.all(args.map(a => deepDecode(a)));
      // 2. Execute tool
      const result = await originalCall.apply(this, decodedArgs);
      // 3. Tokenize output
      if (typeof result === 'string' || typeof result === 'object') {
          return await deepEncodePII(result);
      }
      return result;
    };
    console.info("[llamaindex-magic] active: wrapping BaseTool.prototype.call");
  } catch (e) {
    console.warn("llamaindex not installed; maskLlamaIndexHooks will have no effect.");
  }
}
