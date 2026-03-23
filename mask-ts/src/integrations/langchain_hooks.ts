/**
 * LangChain integration for Mask Privacy SDK.
 *
 * Provides:
 *   - MaskCallbackHandler — plugs into LangChain's callback system.
 *   - MaskToolWrapper     — wraps any callable for auto-encode/decode.
 *   - secureTool         — drop-in decorator/wrapper for tools.
 */

import { deepDecode, deepEncodePII } from '../core/utils';
import { getLogger } from '../telemetry/audit_logger';

const logger = getLogger('mask.integrations.langchain');

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
        const { BaseCallbackHandler } = require('@langchain/core/callbacks/base');

        return class MaskCallbackHandler extends BaseCallbackHandler {
            name = "MaskPrivacyHandler";

            async handleToolStart(tool: any, input: string, runId: string, parentRunId?: string, tags?: string[], metadata?: Record<string, any>, inputs?: Record<string, any>): Promise<void> {
                if (inputs) {
                    logger.info(`[pre-hook] decoding tool inputs for run ${runId}`);
                    const decoded = await deepDecode(inputs);
                    Object.assign(inputs, decoded);
                }
            }

            async handleToolEnd(output: string, runId: string, parentRunId?: string): Promise<void> {
                if (output && typeof output === 'string') {
                    logger.info(`[post-hook] encoding tool output for run ${runId}`);
                    // Note: LangChain callback handleToolEnd receives output as string.
                    // We log the encoding event for audit but cannot mutate the string in-place.
                    // For full output protection, use secureTool() or MaskToolWrapper instead.
                }
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
