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
*   **Local Audit Logger:** An asynchronous AuditLogger that buffers privacy events to a local SQLite database and emits structured JSON logs for SIEM ingestion.

---

## Advanced Architecture & Security Guarantees

While Mask can be run globally via environment variables, the underlying SDKs are highly sophisticated and designed for multi-tenant, zero-trust environments.

### 1. True Deterministic Vaultless FPE
Mask utilizes **Deterministic Format-Preserving Encryption (HMAC-SHA256)** for structured PII. If the LLM generates a prompt containing the same email address 50 times in a single session, Mask generates the *exact same Format-Preserving Token* every time. This mathematically accelerates encryption performance and crucially, prevents the LLM from hallucinating due to seeing inconsistent tokens for the same underlying entity, preserving critical reasoning context without exposing real data to the model. While token generation is deterministic and vaultless (requiring no database lookup to create), the SDKs utilize your configured vault backend for secure reversal mappings. This ensures high-fidelity audit trails and data recovery while maintaining the performance benefits of deterministic generation.

### 2. Heuristic Safety mathematically guaranteed
It is catastrophic if an SDK misidentifies a user's *real* SSN as a "token" and accidentally passes it in plaintext to an LLM. Mask's `looksLikeToken()` / `looks_like_token()` heuristic algorithm strictly uses universally invalid prefixes. 
* SSN tokens always begin with `000` (The Social Security Administration has never issued an Area Number of 000).
* Routing tokens always begin with `0000` (The Federal Reserve valid range starts at 01).
* Credit Card tokens use the `4000-0000-0000` Visa reserved test BIN. 
By generating statistically impossible tokens, Mask guarantees it will never accidentally swallow real PII.

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

## Telemetry and Compliance
The SDKs include a thread-safe, asynchronous AuditLogger built-in. 

As your agents encrypt and decrypt data, the logger buffers these privacy events (Action, Agent, TTL). **Raw PII is never logged.** 

Audit events are stored locally in a SQLite database (`.mask_audit.db`) and flushed to stdout as structured JSON. Pipe them into your existing Datadog or Splunk agents to generate compliance reports for your SOC2, HIPAA, or PCI-DSS auditors proving that your LLM infrastructure properly isolates sensitive data.

---

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Mask AI Solutions
