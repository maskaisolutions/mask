# Mask: Just-in-Time AI Agent Security

Contact: millingtonsully@gmail.com

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Mask is an enterprise-grade AI Data Loss Prevention (DLP) infrastructure. It acts as the runtime enforcement layer between your Large Language Models (LLMs) and your active tool execution environment, ensuring that LLMs never see raw PII or sensitive financial records, while maintaining flawless functional execution for the end user.

---

## The Problem Space: LLM Data Leakage

As Large Language Model (LLM) agents gain autonomy, they become deeply integrated into enterprise systems, often requiring access to highly sensitive information such as Personally Identifiable Information (PII) and confidential financial records.

The core vulnerability in standard agentic architectures is that sensitive data retrieved by tools is injected as plain-text directly into the LLM's context window. This creates severe compliance and security risks:
- **Data Leakage:** Plain-text PII can be logged by external LLM providers, violating data residency laws or compliance frameworks (SOC2, HIPAA, PCI-DSS).
- **Inadvertent Disclosure:** If an agent is compromised via prompt injection or malicious instructions, it can be manipulated into exfiltrating the plain-text data it actively holds in its context.

## The Solution: Privacy by Design

Mask utilizes a **Two-Layer Strategy** to solve the data leakage problem, splitting responsibilities between a local runtime environment (The Data Plane) and a centralized governance platform (The Control Plane).

Instead of trusting the LLM to safeguard plain-text data, the system strictly enforces cryptographic boundaries using **Just-In-Time (JIT) Encryption and Decryption Middleware**. 
1. The LLM only ever "sees" and reasons over scrambled, encrypted cyphertext.
2. When the LLM decides to call a specific authorized tool (e.g., querying a database), a **Pre-Tool Decryption Hook** intercepts the call. It decrypts the specific parameters required by the tool, allowing the backend function to execute securely with real data.
3. Once the tool finishes, a **Post-Tool Encryption Hook** instantly intercepts the output, detects sensitive entities, and encrypts them *before* the result is returned to the LLM's analytical context block.

This guarantees that the LLM can orchestrate workflows involving sensitive data without ever actually exposing the raw data to the model or its remote provider logs. 

Additionally, we solve two critical sub-issues to make this enterprise-ready:
1. **The Statefulness Trap**: Traditional "vaults" break down in multi-node Kubernetes environments. We support pluggable distributed vaults (Redis, DynamoDB, Memcached) so detokenization state is instantly shared across all your horizontally scaled pods.
2. **The Schema Trap**: Strict downstream tools will crash if handed a random token. We use Format-Preserving Tokenization backed by an encrypted vault to generate tokens that retain the exact format of the original data (Emails, US Phones, SSNs, 16-digit Credit Cards, 9-digit Routing Numbers). Tokens look like real data; the real values are stored encrypted and retrieved via the vault.

### How We Handle Data

*   **If the LLM needs to think about the value:** We tokenize it so the LLM only sees a fake-looking value, and we keep the real value encrypted in a vault.
*   **If something is so sensitive that the LLM should never see it at all:** A future version will support skipping the LLM entirely for that field and only sending it to tools/backends.

Real math and real business logic always happen inside tools, after detokenization and decryption, not inside the LLM on fake numbers.

---

## Architectural Overview

### 1. The Data Plane (Mask Open Source SDK)
The Data Plane is the open-source, transparent, auditable runtime execution layer. It lives inside your secure VPC or Kubernetes clusters alongside your AI agents. It acts as the Trojan Horse of security, providing frictionless adoption for engineers while proving cryptographic soundness to security reviewers.

*   **JIT Cryptography Engine:** The core pre-tool decryption and post-tool encryption hooks that intercept and mutate data in-flight.
*   **Format-Preserving Tokenization Router:** Ensures downstream databases and strict schemas don't break when handed a token. Tokens look like real data; the real values are stored encrypted and retrieved via the vault.
*   **Pluggable Distributed Vaults:** Support for enterprise-native caching layers (Redis, DynamoDB, Memcached) to ensure horizontally-scaled edge agents have synchronized access to detokenization mapping.
*   **Telemetry Remote Forwarder:** An asynchronous AuditLogger that buffers privacy events and securely POSTs them to the Control Plane API without blocking LLM execution.

### 2. The Control Plane (Mask Enterprise Platform)
The Control Plane is our active Enterprise SaaS offering—a centralized governance platform for security orchestration. Coming soon.

The Control Plane manages:
*   **Unified Dashboard:** Visualizes usage and storage metrics across your environment.
*   **Tenant & API Key Management:** Manage API keys and role-based access control for isolated environments.
*   **Vault Configuration UI:** Provision and monitor our managed, hosted vaults. We offer Ephemeral Memory Vaults cleared daily, and highly available Persistent Vaults with customizable retention policies based on your subscription tier.
*   **Audit Log Viewer:** Explore telemetry events and generate one-click compliance reports for SOC2, HIPAA, and PCI-DSS.
*   **Key Management Center:** Automate rotation of symmetric encryption keys and track key status without relying on static local environment variables.
*   **Billing & Subscriptions:** Transparent tracking of Protected Entities and metered overage.

---

## Advanced Architecture & Security Guarantees

While Mask can be run globally via environment variables, the underlying SDK is highly sophisticated and designed for multi-tenant, zero-trust environments.

### 1. True Deterministic Vaultless FPE
Mask utilizes **Deterministic Format-Preserving Encryption (HMAC-SHA256)** for structured PII. If the LLM generates a prompt containing the same email address 50 times in a single session, Mask generates the *exact same Format-Preserving Token* every time. This mathematically accelerates encryption performance and crucially, prevents the LLM from hallucinating due to seeing inconsistent tokens for the same underlying entity, preserving critical reasoning context without exposing real data to the model. Structured data like Emails, Phones, and SSNs do not even require vault storage, guaranteeing infinite horizontal scalability.

### 2. The Explicit `MaskClient` API
For enterprise backend services handling multiple tenants at once, global singletons (environment configurations) are dangerous. Mask natively supports explicit client instantiation. Developers can isolate vaults, crypto engines, and NLP scanners on a per-request basis.

```python
from mask.client import MaskClient
from mask.core.vault import MemoryVault
from mask.core.crypto import CryptoEngine

# Fully isolated instance for strict multi-tenancy
client = MaskClient(
    vault=MemoryVault(),
    crypto=CryptoEngine(tenant_specific_key),
    ttl=3600
)

safe_token = client.encode("user@tenant.com")
```

### 3. Heuristic Safety mathematically guaranteed
It is catastrophic if an SDK misidentifies a user's *real* SSN as a "token" and accidentally passes it in plaintext to an LLM. Mask's `looks_like_token()` heuristic algorithm strictly uses universally invalid prefixes. 
* SSN tokens always begin with `000` (The Social Security Administration has never issued an Area Number of 000).
* Routing tokens always begin with `0000` (The Federal Reserve valid range starts at 01).
* Credit Card tokens use the `4000-0000-0000` Visa reserved test BIN. 
By generating statistically impossible tokens, Mask guarantees it will never accidentally swallow real PII.

### 4. Enterprise Async Support
Mask v0.3.2 introduces native `asyncio` wrappers for all core operations. Calling `aencode()`, `adecode()`, or `ascan_and_tokenize()` allows high-throughput ASGI applications (FastAPI, Quart) to handle PII tokenization without blocking the event loop on cryptographic CPU tasks.

### 5. Pluggable Key Providers (AWS KMS / HashiCorp Vault)
For zero-trust environments, `MASK_ENCRYPTION_KEY` no longer needs to live in a static environment variable. Developers can now inject a `BaseKeyProvider` to fetch secrets dynamically from AWS KMS, Azure Key Vault, or HashiCorp Vault at runtime.

### 6. Remote NLP Scanning
Performance-sensitive deployments can now offload the ~500MB spaCy NLP model to a centralized Presidio Analyzer service using the new `RemotePresidioScanner`. This permits "lightweight" edge agents (e.g., Lambda functions) to run Mask with near-zero memory footprint.

### 7. Sub-string Detokenization
Mask v0.3.3 introduces the "Final Boss" fix: the ability to detokenize PII embedded within larger text blocks (like email bodies or chat messages). While previous versions only handled 1:1 token matches, `detokenize_text()` uses high-performance regex to find and restore all tokens within a paragraph before they hit your tools.

## Installation and Setup

Install the Data Plane core SDK. Core features require cryptography and Presidio; Redis/Dynamo/Memcached/LangChain/LlamaIndex/ADK remain optional extras:
```bash
pip install maskcloud
```

Add optional extras depending on your infrastructure and framework:
```bash
pip install "maskcloud[redis]"       # For Redis vaults
pip install "maskcloud[dynamodb]"    # For AWS DynamoDB vaults
pip install "maskcloud[memcached]"   # For Memcached vaults
pip install "maskcloud[langchain]"   # For LangChain hooks
pip install "maskcloud[llamaindex]"  # For LlamaIndex hooks
pip install "maskcloud[adk]"         # For Google ADK hooks
```


### Installing AI Models
Mask uses powerful NLP engines for PII detection. Install the `spacy` extra and then download your preferred model:
```bash
# 1. Install with spaCy support
pip install "maskcloud[spacy]"

# 2. Download the NLP model (choose one)
python -m spacy download en_core_web_sm  # Small (~12MB, Fast)
python -m spacy download en_core_web_md  # Standard (~40MB, Balanced)
python -m spacy download en_core_web_lg  # Large (~560MB, High Accuracy)
```

For a typical production environment, you might combine extras:
```bash
pip install "maskcloud[spacy,redis]"
python -m spacy download en_core_web_lg
```


### Async & Remote Scanner Support
v0.3.2 adds `httpx` as an optional dependency for remote scanning. If you intend to use the `RemotePresidioScanner`, install the extra:
```bash
pip install "maskcloud[remote]"
```

### Environment Configuration

Before running your agents, Mask requires an encryption key and a vault backend selection.

#### 1. Configure Key Source
By default, Mask reads from environment variables.
```bash
# Provide your encryption key
export MASK_ENCRYPTION_KEY="..."
export MASK_MASTER_KEY="..."
```

For Enterprise Key Management, set a custom provider in code:
```python
from mask.core.key_provider import set_key_provider, AwsKmsKeyProvider
set_key_provider(AwsKmsKeyProvider(key_id="alias/mask"))
```

#### 2. Select Scanner Type
```bash
# Options: local (default), remote
export MASK_SCANNER_TYPE=remote
export MASK_SCANNER_URL=http://presidio-analyzer:5001/analyze
```

#### 3. Select vault type
export MASK_VAULT_TYPE=redis      # Options: memory, redis, dynamodb, memcached, cloud

# 3. Configure your chosen vault backend
# For Mask Cloud Managed Vaults:
export MASK_API_KEY="..."
# For self-hosted Redis:
export MASK_REDIS_URL=redis://localhost:6379/0
# For self-hosted DynamoDB:
export MASK_DYNAMODB_TABLE=mask-vault
export MASK_DYNAMODB_REGION=us-east-1
# For self-hosted Memcached:
export MASK_MEMCACHED_HOST=localhost
export MASK_MEMCACHED_PORT=11211
```

For production and staging environments, `MASK_ENCRYPTION_KEY` **must** be set;
the SDK will not start without it. The SDK is designed for single-tenant
deployments where one global vault and key serve a single financial institution
or environment.

---

### 1. Unified Async API
All core methods now have non-blocking async variants for use in FastAPI/ASGI environments.
```python
import asyncio
from mask import aencode, adecode, ascan_and_tokenize

async def main():
    token = await aencode("alice@example.com")
    text = await ascan_and_tokenize("Contact " + token)
    print(text)

asyncio.run(main())
```

## Framework Integrations

Mask integrates seamlessly by injecting dynamic, recursive hooks into your agent's execution pipeline. 
* **Pre-Hooks (Decoding)**: Scans the incoming tool arguments, looks up tokens in the Vault, and replaces them with plaintext *before* the function executes.
* **Post-Hooks (Encoding)**: Scans data returning from the tool, encrypts any raw PII found, and hands the tokens back to the LLM.

### 1. LangChain
Mask integrates with LangChain via our explicit `@secure_tool` decorator.

#### Option A: Explicit Decorator (Recommended)
```python
from mask.integrations.langchain_hooks import secure_tool

@secure_tool
def send_email_tool(email: str, message: str) -> str:
    # `email` is guaranteed to be decrypted back to the real address before execution
    return send_email_backend(email, message)
    # The return string is automatically scanned, and any PII emitted is encrypted into tokens
```

#### Option B: Magic Hooks (Deprecated)
```python
from mask.integrations.langchain_hooks import mask_langchain_hooks

# Note: Deprecated in v0.3.0, to be removed in v1.0
with mask_langchain_hooks():
    # All tools used within this block are automatically protected
    agent_executor.invoke({"input": "Contact alice@example.com"})
```

#### Option B: Explicit Wrapper
```python
from langchain.agents import AgentExecutor
from mask.integrations.langchain_hooks import MaskCallbackHandler, MaskToolWrapper

# Wrap your tools so arguments are automatically detokenized and outputs re-tokenized
secure_tools = [MaskToolWrapper(my_email_tool)]

# Add the callback handler (for logging/audit only)
agent_executor = AgentExecutor(
    agent=my_agent,
    tools=secure_tools,
    callbacks=[MaskCallbackHandler()]
)
```

### 2. LlamaIndex
Use the magic context manager or explicit wrappers.

#### Option A: Magic Hooks
```python
from mask.integrations.llamaindex_hooks import mask_llamaindex_hooks

with mask_llamaindex_hooks():
    # Tools called by the query engine will be protected
    response = query_engine.query("Send email to bob@gmail.com")
```

#### Option B: Explicit Wrapper
```python
from llama_index.core.tools import FunctionTool
from mask.integrations.llamaindex_hooks import MaskToolWrapper

# Wrap the callable directly for input detokenization and output tokenization
secure_email_tool = FunctionTool.from_defaults(
    fn=MaskToolWrapper(my_email_function),
    name="send_email",
    description="Sends a secure email"
)
```

### 3. Google ADK
Use decrypt_before_tool and encrypt_after_tool; they protect args and responses (strings, dicts, lists) with tokenization.
```python
from google.adk.agents import Agent
from mask.integrations.adk_hooks import decrypt_before_tool, encrypt_after_tool

secure_agent = Agent(
    name="secure_assistant",
    model=...,
    tools=[...],
    before_tool_callback=decrypt_before_tool, # Protects arguments
    after_tool_callback=encrypt_after_tool,   # Protects responses
)
```

---

## Testing and Verification

### The Test Suite
The SDK is highly comprehensive and fully verified with a native `pytest` suite. It ensures cryptographic integrity, FPE format compliance, asynchronous telemetry, and distributed vault TTL expiry across all layers.

#### Core Tests (`test_fpe.py`, `test_vault.py`, `test_vault_backends.py`)
- **Format-Preserving Tokenization Integrity:** Validates that tokens preserve their original formats (e.g., emails become `tkn-<hex>@email.com`, SSNs become `000-00-<4 digits>`) to ensure downstream regex and schema validators do not break.
- **Memory Vaults:** Verifies fundamental `store()`, `retrieve()`, `delete()`, TTL mechanics, and clean token/plaintext roundtrips via the `encode()` and `decode()` API. The public `decode()` helper is **strict** and raises on failure; callers that prefer lenient behaviour should catch `DecodeError` and fall back to the original token themselves.
- **Distributed Vaults:** Mocks `boto3` and `pymemcache` to guarantee production-grade backends (DynamoDB and Memcached) correctly respect TTL expirations and auto-delete stale rows across distributed architectures.

#### Telemetry Tests (`test_audit_logger.py`)
- **SOC2/HIPAA Trailing:** Validates asynchronous audit event buffering.
- **Resilience:** Proves that network timeouts (`urllib.error.URLError`) when POSTing to the Mask Control Plane are safely swallowed by the daemon thread and will *never* crash the host application.

#### Framework Integrations (`test_hooks.py`, `test_langchain.py`, `test_llamaindex.py`)
- **Recursive Scanners:** Tests `deep_decode` and `deep_encode_pii` (from `mask.core.utils`) to prove nested dictionaries/lists in JSON payloads are correctly scrubbed without mutating the underlying framework data structures.
- **Framework specific hooks:** Validates that LangChain `MaskToolWrapper`, LlamaIndex `FunctionTool` wrappers, and Google ADK pre/post hooks correctly intercept inputs and outputs to enforce the JIT Privacy Middleware.

```bash
uv run pytest tests/ -v
```

### The Interactive Demo (examples/test_agent.py)
You can observe Mask's privacy middleware in action by running the demo script:
```bash
uv run python examples/test_agent.py
```

**What is REAL vs MOCKED in the demo?**
* **REAL**: The Format-Preserving Tokenization generation, the storage of the token into the Vault, and the hook's recursive detokenization algorithm are all executing genuinely.
* **MOCKED**: To save time and API credits for a local demo, the script does not make a real HTTP call to an LLM provider, nor does the mock tool perform real downstream actions. It simulates the LLM's decision so you can observe the middleware pipeline execute flawlessly.

---

## Telemetry and Compliance
The SDK includes a thread-safe, asynchronous AuditLogger built-in (`mask/telemetry/audit_logger.py`). 

As your agents encrypt and decrypt data, the logger buffers these privacy events (e.g., Action: Tokenized Email, Agent: SalesBot, TTL: 600s). **Raw PII is never logged.** 

In enterprise deployments, these logs are automatically forwarded to the **Mask Control Plane** via our Telemetry Ingestion API to power your compliance dashboard and Audit Storage database. Retention policies vary by Cloud tier (7-day history for Basic, 30-day for Pro, Unlimited for Enterprise). 

For open-source or local telemetry evaluation, they can be flushed to stdout as structured JSON and piped into your existing Datadog or Splunk agents to generate compliance reports for your SOC2, HIPAA, or PCI-DSS auditors proving that your LLM infrastructure properly isolates sensitive data.

If your environment does not permit on-disk storage of audit events, you can
disable the local SQLite buffer by setting:

```bash
export MASK_DISABLE_AUDIT_DB=true
```

In this mode, events are still emitted via the logger but never persisted to
`.mask_audit.db` on disk.

---

### v0.3.3 - Sub-string Detokenization (The "Final Boss")
- **Sub-string Support**: Added `detokenize_text()` and `adetokenize_text()` to find and replace tokens embedded within larger paragraphs.
- **Recursive Decoding Update**: `deep_decode()` now uses sub-string detokenization by default, ensuring email bodies and chat messages are fully detokenized before reaching tools.
- **Reliability**: Verified with 74+ tests covering all edge cases.

### v0.3.2 - Enterprise Architectural Rebuild
- **Async Support**: Native `async` wrappers for all core APIs (`aencode`, `adecode`, `ascan_and_tokenize`).
- **Pluggable Key Providers**: Added `key_provider.py` abstraction for AWS KMS and HashiCorp Vault.
- **Remote NLP Scanner**: `RemotePresidioScanner` offloads detection to a remote API, enabling model-less lightweight deployments.
- **Critical Fixes**: 
    - Resolved "Inception" recursive double-masking bug via `looks_like_token` guard.
    - Fixed whitespace-sensitive deduplication edge case by normalizing input strings.

### v0.3.1 - Fix "Privacy Inception" Bug
- **Added Token Guard to `vault.encode()`**: Prevents double-masking of previously generated tokens when directly calling the vault.
- **Improved Scanner Intelligence**: Updated tiered waterfall scanner to automatically skip strings that match the `looks_like_token` heuristic.
- **Enhanced Recursive Reliability**: Resolves the "Inception" loop where tokens were treated as PII in nested tool call loops.

---

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Mask AI Solutions
