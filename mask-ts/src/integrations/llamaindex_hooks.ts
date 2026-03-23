/**
 * LlamaIndex integration for Mask Privacy SDK.
 *
 * Provides a MaskToolWrapper and a "magic" hook for LlamaIndex's tool
 * pipelines to automatically tokenise/detokenise data.
 */

import { deepDecode, deepEncodePII } from '../core/utils';
import { getLogger } from '../telemetry/audit_logger';

const logger = getLogger('mask.integrations.llamaindex');

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
 * Matches the functional Python implementation.
 */
export async function getMaskCallbackHandler() {
    try {
        const { BaseCallbackHandler } = require("llamaindex");
        return class MaskCallbackHandler extends BaseCallbackHandler {
            async onEvent(eventType: string, payload: any, eventId?: string): Promise<void> {
                if (eventType === 'function_call' && payload) {
                    logger.info(`[llamaindex callback] decoding payload for event ${eventId}`);
                    const decoded = await deepDecode(payload);
                    if (typeof payload === 'object') Object.assign(payload, decoded);
                }
            }
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
    logger.info("[llamaindex-magic] active: wrapping BaseTool.prototype.call");
  } catch (e) {
    logger.warn("llamaindex not installed; maskLlamaIndexHooks will have no effect.");
  }
}
