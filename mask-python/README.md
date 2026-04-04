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

Mask utilizes a **Local-First Strategy** to solve the data leakage problem within your secure runtime environment.

Instead of trusting the LLM to safeguard plain-text data, the system strictly enforces cryptographic boundaries using **Just-In-Time (JIT) Encryption and Decryption Middleware**. 
1. The LLM only ever "sees" and reasons over scrambled, encrypted cyphertext.
2. When the LLM decides to call a specific authorized tool (e.g., querying a database), a **Pre-Tool Decryption Hook** intercepts the call. It decrypts the specific parameters required by the tool, allowing the backend function to execute securely with real data.
3. Once the tool finishes, a **Post-Tool Encryption Hook** instantly intercepts the output, detects sensitive entities, and encrypts them *before* the result is returned to the LLM's analytical context block.

This guarantees that the LLM can orchestrate workflows involving sensitive data without ever actually exposing the raw data to the model or its remote provider logs. 

Additionally, the SDK addresses two technical considerations for production use:
1. **Distributed State Management**: Traditional "vaults" may lose state in multi-node environments. Pluggable backends (Redis, DynamoDB, Memcached) ensure detokenization state is shared across all pods.
2. **Schema Compatibility**: Downstream tools frequently require specific formats. Format-Preserving Tokenization (Emails, US Phones, SSNs, etc.) generates tokens that retain the format of original data.

### How We Handle Data (Local-First by Default)

Mask is designed to be **Local-First**. By default, it operates entirely within your application's process using an in-memory vault. This ensures zero latency and maximum privacy out of the box.

*   **Local Use (Standard):** We use a `MemoryVault`. It's fast, free, and keeps data in your RAM. 
*   **Distributed Use (Scalability):** For high-availability or multi-node environments, we provide backends for **Redis** and **DynamoDB**. These are intended for "Enterprise" or future "Hosted" versions where state must be shared across many servers.
*   **Decryption Hooks:** Real math and business logic happen inside your local tools, after Mask has safely swapped the tokens back to real data just-in-time.

---

## Architectural Overview

### The Data Plane (Mask Open Source SDK)
The Data Plane is the open-source, transparent, auditable runtime execution layer. It lives inside your secure VPC or Kubernetes clusters alongside your AI agents. It acts as the Trojan Horse of security, providing frictionless adoption for engineers while proving cryptographic soundness to security reviewers.

*   **JIT Cryptography Engine:** The core pre-tool decryption and post-tool encryption hooks that intercept and mutate data in-flight.
*   **Format-Preserving Tokenization Router:** Ensures downstream databases and strict schemas don't break when handed a token. Tokens look like real data; the real values are stored encrypted and retrieved via the vault.
*   **Pluggable Distributed Vaults:** Support for enterprise-native caching layers (Redis, DynamoDB, Memcached) to ensure horizontally-scaled edge agents have synchronized access to detokenization mapping.
*   **Local Audit Logger:** An asynchronous AuditLogger that buffers privacy events in memory and emits structured JSON logs to stdout for SIEM ingestion.

---

## Advanced Architecture & Security Guarantees

While Mask can be run globally via environment variables, the underlying SDK is highly sophisticated and designed for multi-tenant, zero-trust environments.

### 1. True Deterministic Vaultless FPE
Mask utilizes **Deterministic Format-Preserving Encryption (HMAC-SHA256)** for structured PII. If the LLM generates a prompt containing the same email address 50 times in a single session, Mask generates the *exact same Format-Preserving Token* every time. This mathematically accelerates encryption performance and crucially, prevents the LLM from hallucinating due to seeing inconsistent tokens for the same underlying entity, preserving critical reasoning context without exposing real data to the model. While token generation is deterministic and vaultless (requiring no database lookup to create), the SDK utilizes your configured vault backend for secure reversal mappings. This ensures high-fidelity audit trails and data recovery while maintaining the performance benefits of deterministic generation.


### 2. The Explicit `MaskClient` API
For enterprise backend services handling multiple tenants at once, global singletons (environment configurations) are dangerous. Mask natively supports explicit client instantiation. Developers can isolate vaults, crypto engines, and NLP scanners on a per-request basis.

```python
from mask_privacy.client import MaskClient
from mask_privacy.core.vault import MemoryVault
from mask_privacy.core.crypto import CryptoEngine

# Fully isolated instance for strict multi-tenancy
client = MaskClient(
    vault=MemoryVault(),
    crypto=CryptoEngine(tenant_specific_key),
    ttl=3600
)

safe_token = client.encode("user@tenant.com")
```

### 3. Collision Avoidance
Mask prevents the misidentification of real data as tokens by using universally invalid prefixes for token generation:
* SSN tokens always begin with `000` (The Social Security Administration does not issue Area Numbers of 000).
* Routing tokens always begin with `0000` (The Federal Reserve valid range starts at 01).
* Credit Card tokens use the `4000-0000-0000` Visa reserved test BIN. 

This prefix-based approach ensures that the SDK does not inadvertently process valid PII as an existing token.

### 4. Enterprise Async Support
Mask includes native asyncio wrappers for all core operations. Calling `aencode()`, `adecode()`, or `ascan_and_tokenize()` allows high-throughput ASGI applications (FastAPI, Quart) to handle PII tokenization without blocking the event loop on cryptographic CPU tasks.

### 5. Pluggable Key Providers (AWS KMS / HashiCorp Vault)
For zero-trust environments, `MASK_ENCRYPTION_KEY` can be managed outside of static environment variables. Developers can inject a `BaseKeyProvider` to fetch secrets dynamically from AWS KMS, Azure Key Vault, or HashiCorp Vault at runtime.

### 6. Remote NLP Scanning
Performance-sensitive deployments offload the ~500MB spaCy NLP model to a centralized Presidio Analyzer service using the `RemotePresidioScanner`. This permits "lightweight" edge agents (e.g., Lambda functions) to run Mask with near-zero memory footprint.

### 7. Sub-string Detokenization
Mask includes the ability to detokenize PII embedded within larger text blocks (like email bodies or chat messages). `detokenize_text()` uses high-performance regex to find and restore all tokens within a paragraph before they hit your tools.

### 8. Performance & Scalability
- **Persistent Scanner Pool**: The NLP scanner utilizes a module-level `ThreadPoolExecutor` internally, eliminating thread-churn latency on each call.
- **Probabilistic Vault Cleanup**: `MemoryVault` uses a probabilistic $O(1)$ cleanup strategy to avoid $O(N)$ blocking scans. Frequency is configurable via `MASK_VAULT_CLEANUP_FREQUENCY`.
- **Thread-Safe Singletons**: Core accessors for `Vault`, `KeyProvider`, and `Scanner` are thread-safe and lazily initialized, preventing race conditions during high-concurrency app startup.

## Language-Specific PII Detection (Waterfall Pipeline)

Mask provides high-precision PII detection for **English (en)** and **Spanish (es)**.

### Supported Language Matrix

Mask provides first-class support for the following languages:

| Language | Code | Tier 0 (DLP) | Tier 2 (NLP Engine) |
| :--- | :--- | :--- | :--- |
| **English** | `en` | ✅ Full | spaCy (`en_core_web_sm`) |
| **Spanish** | `es` | ✅ Full | spaCy (`es_core_news_sm`) |

### How the Waterfall Works: The Excising Mechanism

To maintain high performance, the Python SDK does not simply run three separate scans. It uses a **Sequential Mutation** strategy:

1.  **Tier 0 & 1 (The Scouts):** The SDK first runs the high-speed DLP and Regex engines.
2.  **Immediate Tokenization:** Any PII found by these tiers is **immediately replaced** by a token in the string buffer.
3.  **Tier 2 (The Heavy Infantry):** The expensive NLP engine (spaCy/Transformers) only scans the *remaining* text. Because the PII has already been "excised" (cut out and replaced with tokens), the NLP engine doesn't waste compute on data already identified.
4.  **Bypass Logic:** All tiers are "token-aware." If a scan encounter a string that is already a Mask token, it skips it entirely, preventing redundant processing or "double-tokenization."

---

### Configuration & Environment Variables

Configure your multilingual environment using standard variables. These are parsed at runtime by the internal `NlpEngineProvider`.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MASK_LANGUAGES` | `en` | Comma-separated list of supported languages. Supported: `en`, `es`. |
| `MASK_NLP_ENGINE` | `spacy` | Options: `spacy` or `transformers`. |
| `MASK_NLP_MODEL` | *(varies)* | Override the default model (e.g., `Davlan/bert-base-multilingual-cased-ner-hrl`). |
| `MASK_NLP_MAX_WORKERS` | `4` | Number of worker processes to spawn for parallel NLP analysis. |
| `MASK_NLP_TIMEOUT_SECONDS` | `60.0` | Max duration for a single NLP scan before returning original text. |
| `MASK_DYNAMODB_MAX_SOCKETS` | `50` | Max concurrent HTTP sockets for DynamoDB (parity with TS). |

---

### Installation & Model Management

#### 1. Basic Installation
```bash
pip install "mask-privacy[spacy]"
```

#### 2. Pre-loading Models (Required for Production)
Mask will attempt to load the best available model on your system. For predictable results in production/CI, you **must** download the models explicitly:

```bash
# English (Default)
python -m spacy download en_core_web_md

# Spanish support
python -m spacy download es_core_news_md
```

---

### Performance Tuning for Multilingual Use

#### Process Isolation (Avoiding the GIL)
NLP tasks are CPU-bound and can block the Python Global Interpreter Lock (GIL). Mask solves this by running the `AnalyzerEngine` in a persistent **Process Pool**. 

If you are running on a high-core machine, increase parallelism:
```bash
export MASK_NLP_MAX_WORKERS=16
```

#### Latency Benchmarks (Avg. Overhead)
- **DLP Heuristics:** < 5ms
- **spaCy (Local):** 150ms - 300ms
- **Transformers (Local):** 400ms - 900ms
- **Remote Scanner:** 20ms - 50ms (plus network RTT)

---

## Installation and Setup

Install the Data Plane core SDK. Core features require cryptography and Presidio; Redis/Dynamo/Memcached/LangChain/LlamaIndex/ADK remain optional extras:
```bash
pip install mask-privacy
```

Add optional extras depending on your infrastructure and framework:
```bash
pip install "mask-privacy[redis]"       # For Redis vaults
pip install "mask-privacy[dynamodb]"    # For AWS DynamoDB vaults
pip install "mask-privacy[memcached]"   # For Memcached vaults
pip install "mask-privacy[langchain]"   # For LangChain hooks
pip install "mask-privacy[llamaindex]"  # For LlamaIndex hooks
pip install "mask-privacy[adk]"         # For Google ADK hooks
```


### Installing AI Models (Production Ready)
For production environments, air-gapped clusters, or to avoid cold-start latency, use the built-in CLI to pre-cache all required models:

```bash
# 1. Install with spaCy support
pip install "mask-privacy[spacy]"

# 2. Use the CLI to download models for your required languages
export MASK_LANGUAGES="en,es"
python -m mask_privacy.cli cache-models
```

This is the preferred method instead of manual `spacy download` calls, as it ensures compatibility with the SDK's internal engine configuration.


### Async & Remote Scanner Support
The SDK supports `httpx` as an optional dependency for remote scanning. If you intend to use the `RemotePresidioScanner`, install the extra:
```bash
pip install "mask-privacy[remote]"
```

### Environment Configuration

Before running your agents, Mask requires an encryption key and a vault backend selection.

#### Where to set these?
Select the method that best fits your deployment:

1.  **In a `.env` file (Recommended)**: Create a file in your project root.
    ```env
    MASK_LANGUAGES="es,en"
    MASK_ENCRYPTION_KEY="your-key"
    ```
    Then load it using `load_dotenv()` from `python-dotenv`.
2.  **In your Terminal**:
    *   **Bash**: `export MASK_LANGUAGES="es,en"`
    *   **PowerShell**: `$env:MASK_LANGUAGES="es,en"`
3.  **Directly in Python**:
    ```python
    import os
    os.environ["MASK_LANGUAGES"] = "es,en"
    # Ensure this happens BEFORE importing mask_privacy components
    ```

#### 1. Configure Key Source
By default, Mask reads from environment variables.
```bash
# Provide your encryption key
export MASK_ENCRYPTION_KEY="..."
export MASK_MASTER_KEY="..."
```

#### 2. Pluggable Key Management (Enterprise KMS)
For zero-trust environments, Mask supports a pluggable `BaseKeyProvider` architecture. You can inject a custom provider to fetch secrets dynamically from AWS KMS, Azure Key Vault, or HashiCorp Vault.

> [!NOTE]
> All KMS stub providers are designed for **Fail-Shut** operation. If you attempt to use a stub provider that is not yet implemented, the SDK will raise a `NotImplementedError` rather than fall back to insecure defaults.

#### 2. Select Scanner Type
```bash
# Options: local (default), remote
export MASK_SCANNER_TYPE=remote
export MASK_SCANNER_URL=http://presidio-analyzer:5001/analyze
```

#### 1. Security Guardrails: Fail-Shut by Default

To prevent accidental data leakage, Mask defaults to a **Fail-Shut** strategy. If the Vault or Key Provider is unreachable, the SDK will raise a `MaskVaultConnectionError`.

> [!IMPORTANT]
> **Environment Modes:**
> - **Production (Default):** Fail-Shut enabled. Strictly protects PII.
> - **Development:** Set `MASK_ENV=dev` to allow "Fail-Open" behavior (PII is returned as-is if the vault fails).

#### 2. Model Pre-caching CLI

For production air-gapped environments or to avoid "cold-start" latency, use the model pre-caching tool:

```bash
# Cache English and Spanish models to a specific directory
export MASK_MODEL_CACHE_DIR="./models"
python -m mask_privacy.cli cache-models --languages en,es --engine spacy
```

#### 3. Select vault type
export MASK_VAULT_TYPE=redis      # Options: memory, redis, dynamodb, memcached

# 3. Configure your chosen vault backend
# For Redis:
export MASK_REDIS_URL=redis://localhost:6379/0
# For DynamoDB:
export MASK_DYNAMODB_TABLE=mask-vault
export MASK_DYNAMODB_REGION=us-east-1
# For Memcached:
export MASK_MEMCACHED_HOST=localhost
export MASK_MEMCACHED_PORT=11211

#### 4. Security & Performance (Optional)
# Enable strict mode to refuse startup without MASK_ENCRYPTION_KEY
export MASK_STRICT_PROD=true

# Configure NLP thread pool size (default: 4)
export MASK_NLP_MAX_WORKERS=8

# Configure Blind Index Salt (Optional)
export MASK_BLIND_INDEX_SALT="custom-salt-here"

> [!IMPORTANT]
> **Security Warning:** In production, you **must** change the default `MASK_BLIND_INDEX_SALT`. Using the default salt makes your blind indices vulnerable to pre-computed hash (rainbow table) attacks across different SDK installations.

# Configure MemoryVault cleanup aggressiveness (default: 0.01)
export MASK_VAULT_CLEANUP_FREQUENCY=0.05
```

For production and staging environments, `MASK_ENCRYPTION_KEY` **must** be set;
the SDK will not start without it.

#### 5. DLP Pipeline Configuration (Optional)
```bash
# NLP scan timeout (seconds, default: 60.0)
export MASK_NLP_TIMEOUT_SECONDS=15

# Restrict DLP categories to scan (comma-separated; default: all)
# Options: FINANCIAL, CONTACT, PERSONAL, HEALTHCARE, IDENTITY_US, IDENTITY_INTL, VEHICLE, CORPORATE
# export MASK_DLP_CATEGORIES=FINANCIAL,IDENTITY_INTL
```

---

### 1. Unified Async API
All core methods have non-blocking async variants for use in FastAPI/ASGI environments. They are truly non-blocking, natively utilizing `AsyncRedisVault` under the hood for data caching, and properly offloading any blocking execution to explicitly managed thread pools to prevent thread exhaustion.
```python
import asyncio
from mask_privacy import aencode, adecode, ascan_and_tokenize

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
from mask_privacy.integrations.langchain_hooks import secure_tool

@secure_tool
def send_email_tool(email: str, message: str) -> str:
    # `email` is guaranteed to be decrypted back to the real address before execution
    return send_email_backend(email, message)
    # The return string is automatically scanned, and any PII emitted is encrypted into tokens
```

#### Option B: Explicit Wrapper
```python
from langchain.agents import AgentExecutor
from mask_privacy.integrations.langchain_hooks import MaskCallbackHandler, MaskToolWrapper

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
from mask_privacy.integrations.llamaindex_hooks import mask_llamaindex_hooks

with mask_llamaindex_hooks():
    # Tools called by the query engine will be protected
    response = query_engine.query("Send email to bob@gmail.com")
```

#### Option B: Explicit Wrapper
```python
from llama_index.core.tools import FunctionTool
from mask_privacy.integrations.llamaindex_hooks import MaskToolWrapper

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
from mask_privacy.integrations.adk_hooks import decrypt_before_tool, encrypt_after_tool

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
The SDK is verified with a `pytest` suite covering cryptographic integrity, FPE format compliance, asynchronous telemetry, and distributed vault TTL expiry.

#### Core Tests (`test_fpe.py`, `test_vault.py`, `test_vault_backends.py`)
- **Format-Preserving Tokenization Integrity:** Validates that tokens preserve their original formats (e.g., emails become `tkn-<hex>@email.com`, SSNs become `000-00-<4 digits>`) to ensure downstream regex and schema validators do not break.
- **Memory Vaults:** Verifies fundamental `store()`, `retrieve()`, `delete()`, TTL mechanics, and clean token/plaintext roundtrips via the `encode()` and `decode()` API. The public `decode()` helper is **strict** and raises on failure; callers that prefer lenient behaviour should catch `DecodeError` and fall back to the original token themselves.
- **Distributed Vaults:** Mocks `boto3` and `pymemcache` to guarantee production-grade backends (DynamoDB and Memcached) correctly respect TTL expirations and auto-delete stale rows across distributed architectures.

#### Telemetry Tests (`test_audit_logger.py`)
- **SOC2/HIPAA Trailing:** Validates asynchronous audit event buffering and local SQLite persistence.

#### Framework Integrations (`test_hooks.py`, `test_langchain.py`, `test_llamaindex.py`)
- **Recursive Scanners:** Tests `deep_decode` and `deep_encode_pii` (from `mask_privacy.core.utils`) to prove nested dictionaries/lists in JSON payloads are correctly scrubbed without mutating the underlying framework data structures.
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
The SDK includes a thread-safe, asynchronous AuditLogger built-in (`mask_privacy/telemetry/audit_logger.py`). 

As your agents encrypt and decrypt data, the logger buffers these privacy events (e.g., Action: Tokenized Email, Agent: SalesBot, TTL: 600s). **Raw PII is never logged.** 

Audit events are buffered in memory and flushed periodically to stdout as structured JSON. Pipe these logs into your existing Datadog or Splunk agents to generate compliance reports for your SOC2, HIPAA, or PCI-DSS auditors proving that your LLM infrastructure properly isolates sensitive data.

> [!NOTE]  
> The `AuditLogger` provides graceful shutdown hooks (`SIGTERM`, `SIGINT`) to ensure buffer flushing. To avoid hijacking your primary Web Server (like FastAPI or Uvicorn), you must explicitly opt-in by calling `get_audit_logger().register_signals()`.

To prevent memory issues in high-volume environments, the buffer size can be capped:

```bash
export MASK_AUDIT_MAX_BUFFER_SIZE=5000
```



## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Mask AI Solutions
