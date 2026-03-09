import sys
import os
import asyncio

# Add project root and examples directory to path for demo purposes
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from mask import encode
from mask.integrations.adk_hooks import decrypt_before_tool
from secure_vault.email_tool import send_secure_email

class MockTool:
    name = "send_secure_email"

class MockToolContext:
    agent_name = "secure_data_assistant"

async def run_demo():
    print("\nStarting Mask JIT Micro-Vault detokenization demo (NON-PRODUCTION)...")
    
    # 1. The local application generates a token for the user's email
    real_email = "user1@example.com"
    secure_token = encode(real_email)
    
    print("\n[app] Intercepted PII. Storing in Micro-Vault...")
    print(f"[app] Vault mapping: {secure_token} -> {real_email}")
    
    # 2. We pass ONLY the token to the LLM
    print(f"\n[mask -> llm] Passing tokenized context to LLM:")
    print(f"   Context: {{'user:email': '{secure_token}'}}")
    
    # 3. Simulate the LLM deciding to call the tool with the token
    print("\n[llm -> mask] LLM reasoned successfully. Calling tool `send_secure_email` with tokenized argument...")
    llm_tool_call_args = {
        "email_address": secure_token,
        "subject": "Welcome to Mask!",
        "message": "Your Micro-Vault architecture is secure."
    }
    
    # 4. Mask PRE-HOOK intercepts the tool call BEFORE execution
    print("\n[mask jit detokenization hook]")
    mock_tool = MockTool()
    mock_ctx = MockToolContext()
    
    decrypt_before_tool(mock_tool, llm_tool_call_args, mock_ctx)
    
    # 5. Execute the actual tool with the detokenized arguments
    print("\n[system] Executing tool with detokenized payload (prints plaintext PII in this demo):")
    send_secure_email(**llm_tool_call_args)
    
    print("\nVerification complete: The LLM only saw the token, but the tool triggered with the plaintext.")

if __name__ == "__main__":
    asyncio.run(run_demo())
