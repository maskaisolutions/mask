# Mask: Just-in-Time Privacy SDKs for AI Agents

Contact: millingtonsully@gmail.com

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Mask is an enterprise-grade AI Data Loss Prevention (DLP) layer for AI Agents. It intercepts data flowing between LLMs and tool execution environments, ensuring sensitive data (PII) is encrypted with **Format-Preserving Encryption (FPE)** while maintaining flawless functional execution.

## Why Mask?

Standard agentic architectures inject raw PII into LLM context windows, creating massive data leakage risks (SOC2, HIPAA, PCI-DSS violations). 

Mask provides a **Local-First, Just-In-Time (JIT) Encryption** middleware:
1. **Masking:** Sensitive entities are detected and replaced with scrambled, format-preserving ciphertext tokens.
2. **JIT Unmasking:** A **Pre-Tool Decryption Hook** intercepts tool calls, automatically restoring real values for the authorized backend function.
3. **Re-Masking:** A **Post-Tool Encryption Hook** catches any new PII in the tool's output before it returns to the LLM.

---

## Repository Structure

- **[Python SDK](./mask-python)**: Support for LangChain, LlamaIndex, and Google ADK.
- **[TypeScript SDK](./mask-ts)**: High-performance implementation for Node.js and modern JS.

---

## 2-Tier Model-Augmented Waterfall

Mask uses a **Sequential Mutation** strategy to maximize precision and minimize neural hallucinations:

| Tier | Method | Speed | Description |
|------|--------|-------|-------------|
| **0 — Deterministic** | Registry + Checksums + Context | ⚡ Fastest | High-precision matches for IDs (SSN, DNI), Financials (IBAN, CC), and Contact info. |
| **1 — Probabilistic** | Transformer Models (NER) | 🐢 Slow | Standardized fuzzy detection for **PERSON**, **LOCATION**, and **ORGANIZATION**. |

Already-tokenized data is skipped by the neural tier to prevent entity collisions.

## Language Support

High-performance PII detection for **English (en)** and **Spanish (es)**.
- [**Read the Language Support Guide**](MULTILINGUAL.md) for benchmarks and setup.

## Supported Data Types

Mask handles **50+ core PII types** across categories including:
- **Financial:** SSN, Credit Cards, IBAN, ABA Routing, Bitcoin/ETH, Spanish CCC/IBAN.
- **Contact:** Email, Phone (Intl), IPv4/v6, MAC Address.
- **Identity:** Passport, EIN/Tax ID, Spanish DNI/NIE, ES NUSS, Canadian SIN, UK NINO.
- **Healthcare/Vehicle:** Medical IDs, DEA, VIN, License Plates.

---

## Architectural Highlights

- **Deterministic FPE:** Token generation is HMAC-based; the same PII yields the same token within a session, preserving LLM reasoning context without data exposure.
- **Collision Avoidance:** Tokens use universally invalid prefixes (e.g., SSN `000-...`, CC `4000-...`) to prevent misidentification.
- **Pluggable Vaults:** Sync state across clusters using **Redis**, **DynamoDB**, or **Memcached**. Defaults to `MemoryVault`.
- **Audit Logging:** Thread-safe, asynchronous JSON logging for SIEM ingestion (Datadog, Splunk).

---

## Installation

### Python
```bash
pip install mask-privacy
```

### TypeScript
```bash
npm install mask-privacy
```

[Full Installation & Framework Setup Guide](./mask-python/README.md#installation-and-setup)

---

## Security Guardrails: Fail-Shut by Default

To protect production data, Mask SDKs use a **Fail-Shut** strategy.

> [!IMPORTANT]
> **Secure by Default:** If a vault or Key Provider is unreachable, the SDK will **halt and throw an error** rather than returning plaintext PII.
> **Development:** Set `MASK_ENV=dev` to enable "Fail-Open" behavior.

## Core Configuration

Managed via environment variables:
- `MASK_FAIL_STRATEGY=closed`: (Default) Force halt on vault failure.
- `MASK_NLP_MAX_WORKERS`: Tune detection throughput (CPU cores).
- `MASK_BLIND_INDEX_SALT`: Custom salt for blind indexing hash.

[Full Configuration Reference](./mask-python/README.md#environment-configuration)

---

## License

Apache License, Version 2.0.
Copyright (c) 2026 Mask AI Solutions
sk AI Solutions
