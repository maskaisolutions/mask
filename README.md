# Mask: Just-in-Time Privacy SDKs for AI Agents

Contact: millingtonsully@gmail.com

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Mask is an enterprise-grade AI Data Loss Prevention (DLP) infrastructure. It acts as the runtime enforcement layer between your Large Language Models (LLMs) and your active tool execution environment, ensuring that LLMs never see raw PII or sensitive financial records, while maintaining flawless functional execution for the end user.

This repository is a monorepo containing multiple language-specific SDKs.

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

Additionally, we address two technical considerations to ensure enterprise compatibility:
1. **Distributed State Management**: Traditional "vaults" can lose state in multi-node Kubernetes environments. We support pluggable distributed vaults (Redis, DynamoDB, Memcached) so detokenization state is shared across all pods.
2. **Schema Compatibility**: Downstream tools frequently require specific formats. We use Format-Preserving Tokenization backed by an encrypted vault to generate tokens that retain the format of the original data (Emails, US Phones, SSNs, 16-digit Credit Cards, 9-digit Routing Numbers). 

### How We Handle Data (Local-First by Default)

Mask is designed to be **Local-First**. By default, it operates entirely within your application's process using an in-memory vault. This ensures zero latency and maximum privacy out of the box.

*   **Local Use (Standard):** We use a `MemoryVault`. It's fast, free, and keeps data in your RAM. 
*   **Local NLP (TypeScript):** The TS SDK includes a built-in Transformers-based scanner (`LocalTransformersScanner`) by default, enabling high-accuracy PII detection without external dependencies.
*   **Distributed Use (Scalability):** For high-availability or multi-node environments, we provide backends for **Redis** and **DynamoDB**.
*   **Decryption Hooks:** Real math and business logic happen inside your local tools, after Mask has safely swapped the tokens back to real data just-in-time.

---

## Repository Structure

- **[Python SDK](./mask-python)**: The primary Python implementation with support for LangChain, LlamaIndex, and Google ADK.
- **[TypeScript SDK](./mask-ts)**: The TypeScript/JavaScript implementation for Node.js and modern JS environments.

---

## Architectural Overview

### The Data Plane (Mask Open Source SDKs)
The Data Plane is the open-source, transparent, auditable runtime execution layer. It lives inside your secure VPC or Kubernetes clusters alongside your AI agents. It acts as the Trojan Horse of security, providing frictionless adoption for engineers while proving cryptographic soundness to security reviewers.

*   **JIT Cryptography Engines:** The core pre-tool decryption and post-tool encryption hooks that intercept and mutate data in-flight.
*   **Format-Preserving Tokenization Router:** Ensures downstream databases and strict schemas don't break when handed a token. Tokens look like real data; the real values are stored encrypted and retrieved via the vault.
*   **Pluggable Distributed Vaults:** Support for enterprise-native caching layers (Redis, DynamoDB, Memcached) to ensure horizontally-scaled edge agents have synchronized access to detokenization mapping.
*   **Local Audit Logger:** An asynchronous AuditLogger that buffers privacy events in memory and emits structured JSON logs to stdout for SIEM ingestion (Datadog, Splunk, etc.).

---

## Heuristic-First DLP Architecture

Mask implements a **3-tier Waterfall Detection Pipeline** that maximises speed and accuracy by running the cheapest, most deterministic checks first:

| Tier | Method | Speed | Description |
|------|--------|-------|-------------|
| **0 — DLP Heuristic** | Regex + Checksum + Proximity Scoring | ⚡ Fastest | Structured patterns with hard-validation (Luhn, IBAN Mod-97, Spanish DNI) and proximity-weighted confidence boosting. |
| **1 — Deterministic Regex** | Format-specific regex | ⚡ Fast | Legacy email, phone, SSN, CC patterns with ABA/Luhn checksums. |
| **2 — Probabilistic NLP** | Transformer models (spaCy / HuggingFace) | 🐢 Slow | Catches unstructured entities (names, organisations) that regex cannot identify. |

### How the Waterfall Actually Works: The Excising Mechanism

To maintain high performance, Mask does not simply run three separate scans. It uses a **Sequential Mutation** strategy:

1.  **Tier 0 & 1 (The Scouts):** The SDK first runs the high-speed DLP and Regex engines.
2.  **Immediate Tokenization:** Any PII found by these tiers is **immediately replaced** by a token in the string buffer.
3.  **Tier 2 (The Heavy Infantry):** The expensive NLP engine (Transformer/spaCy) only scans the *remaining* text. Because the PII has already been "excised" (cut out and replaced with tokens), the NLP engine doesn't waste compute on data that has already been accurately identified.
4.  **Bypass Logic:** All tiers are "token-aware." If a scan encounters a string that is already a Mask token, it skips it entirely, preventing redundant processing or "double-tokenization."

### Language Support

Mask provides high-performance PII detection for **English (en)** and **Spanish (es)**.

Our 3-tier waterfall pipeline is language-aware, using locale-specific regex patterns and optimized NLP models.

[**Read the Language Support Guide**](MULTILINGUAL.md) for detailed technical nuances, model setup, and latency benchmarks.

---

### Language Detection

The DLP pipeline includes a **Language Context Resolver** that uses Unicode-block heuristics to select locale-specific patterns:

| Language | Detection Method | Locale-Specific Patterns |
|----------|-----------------|-------------------------|
| English (default) | Latin-only fallback | Standard US/UK PII |
| Spanish | `ñ`, `¡`, `¿` | Spanish honorifics (Sr/Sra/Srta), Spanish addresses (Calle/Avenida/Paseo) |


### Proximity-Weighted Confidence Scoring

Each candidate match is scored using a logarithmic-decay proximity model:

```
confidence = baseRisk + Σ(keywordBoost / (1 + ln(1 + distance)))
```

Where `distance` is the character offset between match and each context keyword. This ensures that an ambiguous pattern (e.g., a 9-digit number) only triggers as sensitive data when relevant keywords like "routing" or "bank" appear nearby.

### 28 Core Supported Data Types

| Category | Types |
|----------|-------|
| **Financial** | US SSN, Credit Card (Visa/MC/Amex/Discover), IBAN, SWIFT/BIC, ABA Routing, Bank Account, Bitcoin, Ethereum |
| **Contact** | Email, Phone (US/Intl incl. TR/SA/UAE), IPv4, IPv6, MAC Address |
| **Personal** | Date of Birth, US Driver's License, US Passport |
| **Identity (US)** | EIN/Tax ID |
| **Identity (Intl)** | UK NINO, Canadian SIN, Spanish DNI/NIE |
| **Vehicle** | VIN (with check-digit validation), License Plate |
| **Healthcare** | Medical Record ID, Medicare ID, DEA Number, NPI Number |
| **Corporate** | Employee ID |

---

## Internal Architecture

The SDKs are designed for multi-tenant, zero-trust environments.

### 1. True Deterministic Vaultless FPE
Mask utilizes **Deterministic Format-Preserving Encryption (HMAC-SHA256)** for structured PII. If the LLM generates a prompt containing the same email address 50 times in a single session, Mask generates the *exact same Format-Preserving Token* every time. This mathematically accelerates encryption performance and crucially, prevents the LLM from hallucinating due to seeing inconsistent tokens for the same underlying entity, preserving critical reasoning context without exposing real data to the model. While token generation is deterministic and vaultless (requiring no database lookup to create), the SDKs utilize your configured vault backend for secure reversal mappings. This ensures high-fidelity audit trails and data recovery while maintaining the performance benefits of deterministic generation.

### 2. Collision Avoidance

Mask prevents the misidentification of real data as tokens by using universally invalid prefixes for token generation:
* SSN tokens always begin with `000` (The Social Security Administration does not issue Area Numbers of 000).
* Routing tokens always begin with `0000` (The Federal Reserve valid range starts at 01).
* Credit Card tokens use the `4000-0000-0000` Visa reserved test BIN. 

This prefix-based approach ensures that the SDK does not inadvertently process valid PII as an existing token.

### 3. Pluggable Key Management (Enterprise KMS)
Mask supports a pluggable `BaseKeyProvider` architecture across all SDK languages. This allows enterprises to fetch encryption keys dynamically from AWS KMS, Azure Key Vault, or HashiCorp Vault at runtime, rather than relying on static environment variables.

### 4. System Protections

The SDK provides a **Strict Production Mode** via the `MASK_STRICT_PROD` environment variable. 

When `MASK_STRICT_PROD=true`, Envelope Encryption is required; the SDK will refuse to initialize if `MASK_ENCRYPTED_KEY` is missing in a non-development environment. Additionally, it will halt if an unimplemented KMS stub is used, preventing the use of placeholder keys in production.

---

## Installation Summary

### Python SDK
```bash
pip install mask-privacy
```

### TypeScript SDK
```bash
npm install mask-privacy
```

For detailed installation instructions, including optional extras for Redis, DynamoDB, and various AI frameworks, please refer to the language-specific READMEs:
- [Python Installation & Setup](./mask-python#installation-and-setup)
- [TypeScript Installation & Setup](./mask-ts#installation-and-setup)

---

## Security Guardrails: Fail-Shut by Default

To protect sensitive data in production, Mask SDKs use a **Fail-Shut** strategy by default.

> [!IMPORTANT]
> **Secure by Default:** If a vault (Redis, DynamoDB) or a Key Provider is unreachable, the SDK will **halt and throw an error** rather than returning plaintext PII.
>
> **Development Mode:** To enable "Fail-Open" behavior (where the SDK gracefully returns original text on failure), you **must** explicitly set the environment variable: `MASK_ENV=dev`.

### Model Pre-caching (Air-Gapped Support)

Mask uses large NLP models for PII detection. In production or air-gapped environments where internet access is restricted, use the built-in CLI to pre-download models:

- **Python**: `python -m mask_privacy.cli cache-models --languages en,es`
- **TypeScript**: `npx ts-node src/cli.ts cache-models --languages en,es`

---

## Production Configuration

Mask SDKs support enterprise-grade deployments with high throughput. All configuration is managed via environment variables for zero-code portability.

### Where to set environment variables?
You have three common options for configuring the SDK:

1.  **In a `.env` file (Recommended)**: Create a file named `.env` in your project root.
    ```env
    MASK_LANGUAGES="es,en"
    MASK_ENCRYPTION_KEY="your-key"
    ```
2.  **In your Terminal**:
    *   **Bash**: `export MASK_LANGUAGES="es,en"`
    *   **PowerShell**: `$env:MASK_LANGUAGES="es,en"`
3.  **Directly in Python/JS**:
    *   **Python**: `os.environ["MASK_LANGUAGES"] = "es,en"`
    *   **Node.js**: `process.env.MASK_LANGUAGES = "es,en"`

### Key Configuration Variables

- `MASK_FAIL_STRATEGY=closed`: Forces the SDK to halt if the Vault or Key Provider is unreachable. The `open` strategy will return plaintext PII, which is intended for local prototyping.
- `MASK_AUDIT_LOG_STRICT=true`: Enforces backpressure on the Audit Logger. If the telemetry buffer fills up, the SDK will block operations until the logs are flushed.
- `MASK_NLP_MAX_WORKERS` (Python only): Controls the number of `ProcessPoolExecutor` workers for the local NLP scanner (default 4). Tune this based on your CPU cores to maximize detection throughput without GIL bottlenecks.
- `MASK_DYNAMODB_MAX_SOCKETS` (TypeScript only): Controls the HTTP agent connection pool size for the DynamoDB vault (default 50). Increase this for extremely high-throughput environments to prevent port exhaustion.
- `MASK_BLIND_INDEX_SALT`: (Optional) Custom salt string for deterministic blind indexing (default: `mask-blind-index`). **Security Warning:** In production, you must change this to prevent pre-computed hash attacks.
- `MASK_VAULT_CLEANUP_FREQUENCY`: (Optional) Controls the aggressiveness of `MemoryVault` cleanup (0.0 to 1.0, default: `0.01` or 1%). Higher values reduce memory but increase CPU overhead.

---

## Telemetry and Compliance
The SDKs include a thread-safe, asynchronous AuditLogger built-in. 

As your agents encrypt and decrypt data, the logger buffers these privacy events (Action, Agent, TTL). **Raw PII is never logged.** 

Audit events are buffered in memory and flushed periodically to stdout as structured JSON. Pipe these logs into your existing Datadog or Splunk agents to generate compliance reports for your SOC2, HIPAA, or PCI-DSS auditors proving that your LLM infrastructure properly isolates sensitive data.

---

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Mask AI Solutions
