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

Additionally, we solve two critical sub-issues to make this enterprise-ready:
1. **The Statefulness Trap**: Traditional "vaults" break down in multi-node Kubernetes environments. We support pluggable distributed vaults (Redis, DynamoDB, Memcached) so detokenization state is instantly shared across all your horizontally scaled pods.
2. **The Schema Trap**: Strict downstream tools will crash if handed a random token. We use Format-Preserving Tokenization backed by an encrypted vault to generate tokens that retain the exact format of the original data (Emails, US Phones, SSNs, 16-digit Credit Cards, 9-digit Routing Numbers). Tokens look like real data; the real values are stored encrypted and retrieved via the vault.

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
*   **Local Audit Logger:** An asynchronous AuditLogger that buffers privacy events to a local SQLite database and emits structured JSON logs for SIEM ingestion.

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

### 3. Heuristic Safety mathematically guaranteed
It is catastrophic if an SDK misidentifies a user's *real* SSN as a "token" and accidentally passes it in plaintext to an LLM. Mask's `looksLikeToken()` heuristic algorithm strictly uses universally invalid prefixes. 
* SSN tokens always begin with `000` (The Social Security Administration has never issued an Area Number of 000).
* Routing tokens always begin with `0000` (The Federal Reserve valid range starts at 01).
* Credit Card tokens use the `4000-0000-0000` Visa reserved test BIN. 
By generating statistically impossible tokens, Mask guarantees it will never accidentally swallow real PII.

### 4. Enterprise Async Support
Mask is built from the ground up for high-concurrency Node.js environments. All core operations are asynchronous and promised-based. Calling `encode()`, `decode()`, or `scanAndTokenize()` allows your event loop to remain unblocked while handling PII tokenization tasks.

### 5. Pluggable Key Providers (AWS KMS / HashiCorp Vault)
For zero-trust environments, `MASK_ENCRYPTION_KEY` no longer needs to live in a static environment variable. Developers can fetch secrets dynamically from AWS KMS, Azure Key Vault, or HashiCorp Vault at runtime and inject them into the `CryptoEngine`.

### 6. Remote NLP Scanning
Performance-sensitive deployments can now offload the NLP models (like spaCy or Presidio) to a centralized service using the `RemotePresidioScanner`. This permits "lightweight" edge workers (e.g., AWS Lambda) to run Mask with near-zero memory footprint.

### 7. Sub-string Detokenization
Mask includes the ability to detokenize PII embedded within larger text blocks (like email bodies or chat messages). `detokenizeText()` uses high-performance regex to find and restore all tokens within a paragraph before they hit your tools.

## Installation and Setup

Install the core SDK via npm:
```bash
npm install mask-privacy
```

Add peer dependencies depending on your infrastructure:
```bash
npm install ioredis          # For Redis vaults
npm install @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb # For DynamoDB vaults
npm install memjs            # For Memcached vaults
```

### Framework Support
Mask supports major AI frameworks via built-in hooks:
- **LangChain**: `@langchain/core`
- **LlamaIndex**: `llamaindex`
- **Google ADK**: `@google/adk`

### Environment Configuration

Before running your agents, Mask requires an encryption key and a vault backend selection.

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

Audit events are stored locally in a SQLite database (`.mask_audit.db`) and flushed to stdout as structured JSON. Pipe them into your existing Datadog or Splunk agents for SOC2/HIPAA compliance reporting.

To disable the local SQLite buffer:
```bash
export MASK_DISABLE_AUDIT_DB=true
```

## License

This project is licensed under the Apache License, Version 2.0.

Copyright (c) 2026 Mask AI Solutions
