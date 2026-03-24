/**
 * Google ADK tool interception hooks.
 *
 * Replaces the hardcoded field-name checks from the original hooks.py
 * with recursive, dynamic token scanning powered by the FPE heuristic
 * detector. Works with *any* tool schema — no config required.
 */

import { deepDecode, deepEncodePII } from '../core/utils';
import { getLogger } from '../telemetry/audit_logger';

const logger = getLogger('mask.integrations.adk');

/**
 * Pre-tool hook: detokenise every Mask token found in args.
 */
export async function decryptBeforeTool(
    tool: any,
    args: Record<string, any>,
    toolContext: any,
    client?: any
): Promise<null> {
    const agentName = toolContext?.agent_name || "unknown";
    const toolName = tool?.name || String(tool);
    logger.info(`[pre-hook] decrypting for ${agentName} → ${toolName}`);

    const decodedArgs = await deepDecode(args, client);
    // Mutate in place (ADK expects args dict to be modified)
    Object.assign(args, decodedArgs);
    return null;
}

/**
 * Post-tool hook: tokenise any raw PII found in args or tool_response.
 */
export async function encryptAfterTool(
    tool: any,
    args: Record<string, any>,
    toolContext: any,
    toolResponse: any,
    client?: any
): Promise<any> {
    const agentName = toolContext?.agent_name || "unknown";
    const toolName = tool?.name || String(tool);
    logger.info(`[post-hook] encrypting for ${agentName} → ${toolName}`);

    // Encrypt any plaintext emails that leaked into the args
    const encodedArgs = await deepEncodePII(args, client);
    Object.assign(args, encodedArgs);

    // Encrypt tool_response if it is a string, dict, or list
    if (typeof toolResponse === 'string' || typeof toolResponse === 'object') {
        const encodedResp = await deepEncodePII(toolResponse, client);
        if (typeof toolResponse === 'object' && !Array.isArray(toolResponse) && typeof encodedResp === 'object') {
            Object.assign(toolResponse, encodedResp);
        }
        return encodedResp;
    }

    return null;
}
