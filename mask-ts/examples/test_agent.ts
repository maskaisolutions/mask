import * as path from 'path';
import { aencode } from '../src/index';
import { decryptBeforeTool } from '../src/integrations/adk_hooks';
import { sendSecureEmail } from './secure_vault/email_tool';

class MockTool {
    name = "send_secure_email";
}

class MockToolContext {
    agent_name = "secure_data_assistant";
}

async function runDemo() {
    console.log("\nStarting Mask JIT Micro-Vault detokenization demo (NON-PRODUCTION)...");
    
    // 1. The local application generates a token for the user's email
    const realEmail = "user1@example.com";
    const secureToken = await aencode(realEmail);
    
    console.log("\n[app] Intercepted PII. Storing in Micro-Vault...");
    console.log(`[app] Vault mapping: ${secureToken} -> ${realEmail}`);
    
    // 2. We pass ONLY the token to the LLM
    console.log(`\n[mask -> llm] Passing tokenized context to LLM:`);
    console.log(`   Context: {'user:email': '${secureToken}'}`);
    
    // 3. Simulate the LLM deciding to call the tool with the token
    console.log("\n[llm -> mask] LLM reasoned successfully. Calling tool `send_secure_email` with tokenized argument...");
    const llmToolCallArgs: any = {
        "emailAddress": secureToken,
        "subject": "Welcome to Mask!",
        "message": "Your Micro-Vault architecture is secure."
    };
    
    // 4. Mask PRE-HOOK intercepts the tool call BEFORE execution
    console.log("\n[mask jit detokenization hook]");
    const mockTool = new MockTool();
    const mockCtx = new MockToolContext();
    
    await decryptBeforeTool(mockTool, llmToolCallArgs, mockCtx);
    
    // 5. Execute the actual tool with the detokenized arguments
    console.log("\n[system] Executing tool with detokenized payload (prints plaintext PII in this demo):");
    sendSecureEmail(llmToolCallArgs.emailAddress, llmToolCallArgs.subject, llmToolCallArgs.message);
    
    console.log("\nVerification complete: The LLM only saw the token, but the tool triggered with the plaintext.");
}

runDemo().catch(console.error);
