# Mask: Just-in-Time AI Agent Security for TypeScript

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

```typescript
import { MaskClient } from 'mask-privacy';
import { MemoryVault } from 'mask-privacy/core/vault';
import { CryptoEngine } from 'mask-privacy/core/crypto';

// Fully isolated instance for strict multi-tenancy
const client = new MaskClient({
    vault: new MemoryVault(),
    crypto: new CryptoEngine(tenantSpecificKey),
    ttl: 3600
});

const safeToken = await client.encode("user@tenant.com");
```

### 3. Collision Avoidance
Mask prevents the misidentification of real data as tokens by using universally invalid prefixes for token generation:
* SSN tokens always begin with `000` (The Social Security Administration does not issue Area Numbers of 000).
* Routing tokens always begin with `0000` (The Federal Reserve valid range starts at 01).
* Credit Card tokens use the `4000-0000-0000` Visa reserved test BIN. 

This prefix-based approach ensures that the SDK does not inadvertently process valid PII as an existing token.

### 4. Enterprise Async Support
Mask is built from the ground up for high-concurrency Node.js environments. All core operations are asynchronous and promised-based. Calling `encode()`, `decode()`, or `scanAndTokenize()` allows your event loop to remain unblocked while handling PII tokenization tasks.

### 5. Pluggable Key Management (Enterprise KMS)
For zero-trust environments, `MASK_ENCRYPTION_KEY` can be managed outside of static environment variables. Mask supports a pluggable `BaseKeyProvider` architecture that allows you to fetch secrets dynamically from dedicated Key Management Services.

#### Supported Providers
*   **EnvKeyProvider (Default)**: Reads from `MASK_ENCRYPTION_KEY` and `MASK_MASTER_KEY`.
*   **AwsKmsKeyProvider (Stub)**: Placeholder for AWS KMS. Requires implementation of `@aws-sdk/client-kms`.
*   **AzureKeyVaultProvider (Stub)**: Placeholder for Azure Key Vault. Requires implementation of `@azure/keyvault-keys`.
*   **HashiCorpVaultProvider (Stub)**: Placeholder for HashiCorp Vault.

> [!NOTE]
> All KMS stub providers are designed for **Fail-Shut** operation. If you attempt to use a stub provider that is not yet implemented, the SDK will throw an `Error` rather than fall back to insecure defaults.

#### Example: Implementing a Custom Provider
If you need to support a specific KMS today, you can easily implement the `BaseKeyProvider` interface:

```typescript
import { BaseKeyProvider, setKeyProvider } from 'mask-privacy/core/key_provider';

class MyCustomKmsProvider extends BaseKeyProvider {
  async getEncryptionKey(): Promise<string> {
    // Logic to fetch from your KMS
    return "your-secret-key";
  }
  async getMasterKey(): Promise<string> {
    return "your-master-key";
  }
}

setKeyProvider(new MyCustomKmsProvider());
```

### 6. Local NLP Scanning (Default)
Performance-sensitive deployments utilize the built-in `LocalTransformersScanner` by default. This uses HuggingFace Transformers to run PII detection locally within your Node.js process, eliminating the need for external NLP services.

### 7. Sub-string Detokenization
Mask includes the ability to detokenize PII embedded within larger text blocks (like email bodies or chat messages). `detokenizeText()` uses high-performance regex to find and restore all tokens within a paragraph before they hit your tools.

## Multilingual PII Detection (Waterfall Pipeline)

Mask is built for the global enterprise. The TypeScript SDK implements a **3-Tier Waterfall Detection** strategy for high-precision PII detection in **English and Spanish** using local ONNX models.

### Supported Language Matrix

Mask provides first-class support for the following languages:

| Language | Code | Tier 0 (DLP) | Tier 2 (NLP Engine) |
| :--- | :--- | :--- | :--- |
| **English** | `en` | ✅ Full | DistilBERT (Simple) |
| **Spanish** | `es` | ✅ Full | BERT Multilingual |

### How the Waterfall Works: The Excising Mechanism

To maintain high performance, the TypeScript SDK does not simply run three separate scans. It uses a **Sequential Mutation** strategy:

1.  **Tier 0 & 1 (The Scouts):** The SDK first runs the high-speed DLP and Regex engines synchronously in the main thread.
2.  **Immediate Tokenization:** Any PII found by these tiers is **immediately replaced** by a token in the string buffer.
3.  **Tier 2 (The Heavy Infantry):** The expensive NLP engine (Transformers.js) only scans the *remaining* text. Because the PII has already been "excised" (cut out and replaced with tokens), the NLP engine doesn't waste compute on data already identified.
4.  **Bypass Logic:** All tiers are "token-aware." If a scan encounter a string that is already a Mask token, it skips it entirely, preventing redundant processing or "double-tokenization."

---

### Configuration & Environment Variables

Configure your language environment using standard variables.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MASK_LANGUAGES` | `en` | Comma-separated language codes. Supported: `en`, `es`. |
| `MASK_NLP_MODEL` | *(varies)* | Override the default model (e.g., `Xenova/bert-base-multilingual-cased-ner-hrl`). |
| `MASK_MODEL_CACHE_DIR` | `~/.cache` | Local directory for storing serialized ONNX models. |
| `MASK_NLP_MAX_WORKERS` | `4` | Number of worker processes/threads for NLP analysis. |
| `MASK_NLP_TIMEOUT_SECONDS` | `60` | Max seconds for a scan before timing out. |

---

### Automatic Model Management

The TypeScript SDK manages AI models automatically via the **Transformers.js** runtime. 

#### 1. Automatic Downloads
When you set `MASK_LANGUAGES` to include non-English languages, the scanner will automatically download the multilingual BERT model from Hugging Face on the first execution and cache it locally.

#### 2. Pre-Warming (Performance)
Upon initialization, the `LocalTransformersScanner` starts a worker pool and "pre-warms" the models. This ensures that the first real request doesn't suffer from high "cold-start" latency.

#### 3. Air-Gapped / Offline Environments
For high-security environments, you can pre-cache models. Run this script in your build pipeline:
```bash
# Set a custom cache directory
export MASK_MODEL_CACHE_DIR="./models"

# Run a dummy scan to trigger the download
node -e "require('mask-privacy').getScanner().scanAndTokenize('John Doe')"

# Bundle the './models' folder with your container
```

---

### Performance & Latency Benchmarks

*Measured on 4-vCPU 8GB RAM Instance (Node.js 20+)*

| Tier | Engine | Avg. Latency | Rationale |
| :--- | :--- | :--- | :--- |
| Tier 0 | DLP (Heuristic) | ~2ms | Main-thread synchronous regex |
| Tier 1 | Regex (Deterministic) | ~1ms | Main-thread synchronous regex |
| Tier 2 | Transformers (Local) | 300ms - 800ms | Offloaded to Worker Threads (Piscina) |

**Total Overhead:** Usually **< 400ms** for standard chat lengths. Mask uses an **Excising Mechanism** to ensure that text already identified in Tiers 0/1 is removed from the NLP buffer, significantly accelerating the heavy Transformer inference.

---

### Installing AI Models (Production Ready)
The TypeScript SDK manages AI models automatically via **Transformers.js**. For production air-gapped environments or to avoid "cold-start" latency, we recommend using the pre-caching CLI:

```bash
npm install @huggingface/transformers # Required extra

# Pre-cache models for English and Spanish
export MASK_LANGUAGES="en,es"
npx mask-privacy cache-models
```

### Framework Support
Mask supports major AI frameworks via built-in hooks:
- **LangChain**: `@langchain/core`
- **LlamaIndex**: `llamaindex`
- **Google ADK**: `@google/adk`

### Environment Configuration

Before running your agents, Mask requires an encryption key and a vault backend selection.

#### Where to set these?
Select the method that best fits your deployment:

1.  **In a `.env` file (Recommended)**: Create a file in your project root.
    ```env
    MASK_LANGUAGES="es,en"
    MASK_ENCRYPTION_KEY="your-key"
    ```
    Then load it using a library like `dotenv`.
2.  **In your Terminal**:
    *   **Bash**: `export MASK_LANGUAGES="es,en"`
    *   **PowerShell**: `$env:MASK_LANGUAGES="es,en"`
3.  **Directly in TypeScript/Node.js**:
    ```typescript
    process.env.MASK_LANGUAGES = "es,en";
    // Ensure this happens BEFORE initializing the MaskClient
    ```

#### 1. Configure Keys
By default, Mask reads from environment variables.
```bash
# Provide your encryption keys
export MASK_ENCRYPTION_KEY="..."
export MASK_MASTER_KEY="..."
```

#### 2. Select Scanner Type
```bash
# Options: local (default), remote
export MASK_SCANNER_TYPE=remote
export MASK_SCANNER_URL=http://presidio-analyzer:5001/analyze
```

#### 3. Select Vault Type
```bash
export MASK_VAULT_TYPE=redis      # Options: memory, redis, dynamodb, memcached

# Configure your chosen vault backend
# For Redis:
export MASK_REDIS_URL=redis://localhost:6379/0
# For DynamoDB:
export MASK_DYNAMODB_TABLE=mask-vault
export MASK_DYNAMODB_REGION=us-east-1
# For Memcached:
export MASK_MEMCACHED_HOST=localhost
export MASK_MEMCACHED_PORT=11211

#### 4. Security Guardrails: Fail-Shut by Default

To prevent accidental data leakage, Mask defaults to a **Fail-Shut** strategy. If the Vault or Key Provider is unreachable, the SDK will throw a `MaskVaultConnectionError`.

> [!IMPORTANT]
> **Environment Modes:**
> - **Production (Default):** Fail-Shut enabled. Strictly protects PII.
> - **Development:** Set `MASK_ENV=dev` to allow "Fail-Open" behavior (PII is returned as-is if the vault fails).

#### 5. Model Pre-caching CLI

For production air-gapped environments or to avoid "cold-start" latency, use the model pre-caching tool:

```bash
# Cache English and Spanish models
export MASK_MODEL_CACHE_DIR="./models"
npx ts-node src/cli.ts cache-models --languages en,es
```

# Configure MemoryVault cleanup aggressiveness (default: 0.01)
export MASK_VAULT_CLEANUP_FREQUENCY=0.05
```

---

### Async Usage Example
```typescript
import { encode, scanAndTokenize } from 'mask-privacy';

async function main() {
    const token = await encode("alice@example.com");
    const text = await scanAndTokenize("Contact " + token);
    console.log(text);
}

main();
```

## Framework Integrations

Mask integrates seamlessly by injecting dynamic, recursive hooks into your agent's execution pipeline. 

### 1. LangChain
Mask integrates with LangChain via our explicit `@secureTool` decorator.

```typescript
import { secureTool } from 'mask-privacy/integrations/langchain_hooks';

const tool = secureTool({
    name: "send_email",
    description: "Sends a secure email",
    func: async (input: { email: string, message: string }) => {
        // `email` is guaranteed to be decrypted back to the real address
        return `Sent to ${input.email}`;
    }
});
```

### 2. LlamaIndex
Use the magic hooks or explicit wrappers.

```typescript
import { maskLlamaIndexHooks } from 'mask-privacy/integrations/llamaindex_hooks';

await maskLlamaIndexHooks(async () => {
    // Tools called within this closure will be protected
    const response = await queryEngine.query("Send email to bob@gmail.com");
});
```

### 3. Google ADK
Use `decryptBeforeTool` and `encryptAfterTool` callbacks.
```typescript
import { decryptBeforeTool, encryptAfterTool } from 'mask-privacy/integrations/adk_hooks';

const agent = new Agent({
    name: "secure_assistant",
    tools: [...],
    beforeToolCallback: decryptBeforeTool,
    afterToolCallback: encryptAfterTool,
});
```

---

## Testing and Verification

### The Test Suite
The SDK is fully verified with a comprehensive `jest` suite. It ensures cryptographic integrity, FPE format compliance, and distributed vault TTL expiry across all layers.

```bash
npm test
```

### The Interactive Demo
Observe the privacy middleware in action:
```bash
npm run demo
```

---

## Telemetry and Compliance
The SDK includes a thread-safe, asynchronous AuditLogger built-in. 

As your agents encrypt and decrypt data, the logger buffers these privacy events (Action, Agent, TTL). **Raw PII is never logged.** 

Audit events are buffered in memory and flushed periodically to stdout as structured JSON. Pipe these logs into your existing Datadog or Splunk agents for SOC2/HIPAA compliance reporting.

The `AuditLogger` includes graceful shutdown hooks (`SIGTERM`, `SIGINT`) to ensure all buffered events are flushed before the process exits.

To prevent memory issues in high-volume environments, the buffer size can be capped:

```bash
export MASK_AUDIT_MAX_BUFFER_SIZE=5000
```

## License

This project is licensed under the Apache License, Version 2.0.

Copyright (c) 2026 Mask AI Solutions
