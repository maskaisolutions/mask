# Multilingual Privacy Pipeline

Mask is built for the global enterprise. While many privacy tools are English-centric, Mask implements a **3-Tier Waterfall Detection** strategy designed for high-performance PII detection across 8 major languages.

## Supported Languages

Mask provides first-class support for:
- 🇺🇸 **English (en)** - Default
- 🇪🇸 **Spanish (es)**
- 🇫🇷 **French (fr)**
- 🇩🇪 **German (de)**
- 🇹🇷 **Turkish (tr)**
- 🇸🇦 **Arabic (ar)**
- 🇯🇵 **Japanese (ja)**
- 🇨🇳 **Chinese (zh)**

---

## How it Works: The Waterfall

Multilingual support is handled uniquely at each tier of the detection pipeline to balance speed and accuracy.

### Tier 0: DLP Heuristic (Fastest)
The DLP engine uses locale-aware regex patterns and checksum validators.
- **Names & Addresses:** Uses script-aware patterns (e.g., matching Japanese Kanji vs. Arabic script).
- **Global IDs:** Supports 50+ international ID formats (Spanish DNI, French INSEE, etc.) with functional checksum validation.
- **Latency:** < 5ms.

### Tier 1: Deterministic (Global Standards)
Tier 1 handles globally standardized formats like Emails, URLs, IP Addresses, and Credit Cards. These patterns are language-agnostic.
- **Latency:** < 2ms.

### Tier 2: Probabilistic NLP (Deep Context)
This tier uses Large Language Models (LLMs) or Named Entity Recognition (NER) to catch context-dependent PII like Names, Organizations, and Locations.

**Python SDK:**
- Uses **spaCy** for most languages (EN, ES, FR, DE, JA, ZH, TR).
- Automatically switches to **Transformers** for Arabic (using `bert-base-multilingual-cased-ner-hrl`) or if explicitly configured.
- **Language Detection:** Automatically detects the input language and routes to the correct model.

**TypeScript SDK:**
- Uses **Transformers.js** with ONNX runtime.
- Defaults to `distilbert-base-uncased-ner-simple` for English.
- Automatically switches to `bert-base-multilingual-cased-ner-hrl` if `MASK_LANGUAGES` includes non-English languages.

---

---

## Configuration & Setup

Mask uses environment variables for zero-code configuration. This ensures that your deployment environment (Dev, Staging, Prod) can have different security and performance profiles.

### Global Environment Variables

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `MASK_LANGUAGES` | `string` | `en` | Comma-separated list of ISO 639-1 language codes (e.g., `en,es,fr,ar`). |
| `MASK_NLP_MODEL` | `string` | *(varies)* | Explicitly override the default NER model. Supports HuggingFace model IDs (e.g., `Xenova/bert-base-multilingual-cased-ner-hrl`). |
| `MASK_NLP_TIMEOUT_SECONDS` | `int` | `30` / `60` | Maximum time to wait for a Tier 2 NLP scan (30s TypeScript, 60s Python). |

### Where to set these?
You have three common options for setting these variables in your environment:

1.  **In a `.env` file (Recommended)**: Create a file named `.env` in your project root.
    ```env
    MASK_LANGUAGES="es,en"
    MASK_NLP_ENGINE="spacy"
    ```
    Then use a library like `python-dotenv` (Python) or `dotenv` (Node.js) to load it.

2.  **In your Terminal**: Set them before running your application.
    *   **Bash/Zsh**: `export MASK_LANGUAGES="es,en"`
    *   **PowerShell**: `$env:MASK_LANGUAGES="es,en"`

3.  **Directly in Code**:
    *   **Python**: `os.environ["MASK_LANGUAGES"] = "es,en"` (set before importing `mask_privacy`).
    *   **TypeScript**: `process.env.MASK_LANGUAGES = "es,en"` (set before initializing `MaskClient`).

### Python-Specific Options (`mask-python`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MASK_NLP_ENGINE` | `spacy` | Options: `spacy` or `transformers`. Arabic always forces `transformers`. |
| `MASK_NLP_MAX_WORKERS` | `4` | Number of processes in the `ProcessPoolExecutor` for parallel NLP analysis. |

### TypeScript-Specific Options (`mask-ts`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MASK_MODEL_CACHE_DIR` | `~/.cache` | Local directory for storing serialized ONNX models. |
| `PISCINA_MAX_THREADS` | `4` | (Internal) Configures the maximum number of worker threads for the NLP pool. |

---

## Technical Nuances

### 1. Language Resolution Strategy
Mask uses a **Unicode-block heuristic** to resolve the language context within the `LanguageContextResolver`. 
- **Short strings (< 15 chars):** Heuristics may default to English if no strong Unicode markers (Kanji, Arabic script) are present.
- **Long strings:** Heuristics calculate the dominant script density to select the correct Tier 0 pattern registry.
- **Explicit Override:** You can pass `language="es"` directly to the client methods if you know the source language in advance.

### 2. Model Mappings (Tier 2 NLP)

#### spaCy Model Matrix (Python)
If `MASK_NLP_ENGINE=spacy`, Mask looks for these models in order of priority (Large → Medium → Small).

| Language | Model Priority |
| :--- | :--- |
| **English** | `en_core_web_lg`, `en_core_web_md`, `en_core_web_sm` |
| **Spanish** | `es_core_news_lg`, `es_core_news_md`, `es_core_news_sm` |
| **French** | `fr_core_news_lg`, `fr_core_news_md`, `fr_core_news_sm` |
| **German** | `de_core_news_lg`, `de_core_news_md`, `de_core_news_sm` |
| **Japanese** | `ja_core_news_lg`, `ja_core_news_md`, `ja_core_news_sm` |
| **Chinese** | `zh_core_web_lg`, `zh_core_web_md`, `zh_core_web_sm` |
| **Turkish** | `tr_core_news_trf`, `en_core_web_lg` |
| **Arabic** | *(Always routes to Transformers)* |

#### Transformers (Python & TypeScript)
By default, any language set including `ar` (Arabic) or any explicit `transformers` request will use:
- **Default:** `bert-base-multilingual-cased-ner-hrl`
- **Fallback (TS):** `distilbert-base-uncased-ner-simple` (for EN-only environments)

### 3. The "Excising" Performance Mechanism

To prevent the O(n) complexity of large Transformer models from bloating response times, Mask uses a **Sequential Mutation** strategy (the "Waterfall"):

1.  **Tier 0/1 (The Scouts):** Identify high-confidence PII (SSNs, Emails, local IDs) synchronously.
2.  **Immediate Tokenization:** These spans are **replaced with temporary tokens** in the buffer.
3.  **Tier 2 (The Heavy Infantry):** Only processes the remaining "non-sensitive" text to find lower-confidence entities (Names, Organizations).
4.  **Bypass Logic:** All tiers are "token-aware," skipping existing tokens to prevent redundant processing.

This ensures that heavy NLP models don't waste compute on data that has already been provably identified by deterministic rules.

---

## Air-Gapped & Offline Environments

In high-security environments where servers lack outbound internet access, you must pre-warm models.

### Python (Pre-install models)
```bash
# Install the SDK
pip install mask-privacy

# Download the required spaCy models manually
python -m spacy download en_core_web_sm
python -m spacy download es_core_news_sm
python -m spacy download fr_core_news_sm
```

### TypeScript (Pre-cache models)
Run a script in your build pipeline with internet access to force a download into a specific directory:
```bash
# Set a custom cache directory
export MASK_MODEL_CACHE_DIR="./models"

# Run a dummy scan to trigger the download
node -e "require('mask-privacy').getScanner().scanAndTokenize('John Doe')"

# Bundle the './models' folder with your application container
```

---

## Latency Benchmarks

*Measured on 4-vCPU 8GB RAM Instance (Standard Cloud VM)*

| Payload Size | Tier 0/1 (DLP) | Tier 2 (spaCy) | Tier 2 (Transformers) |
| :--- | :--- | :--- | :--- |
| **Short (1 sentence)** | < 1ms | ~40ms | ~150ms |
| **Standard (100 words)** | ~3ms | ~120ms | ~450ms |
| **Long (1000 words)** | ~12ms | ~600ms | ~1800ms* |

*\* Note: For large documents, we highly recommend using `MASK_NLP_MAX_WORKERS` to parallelize processing, or offloading to a GPU-backed RemoteScanner.*
