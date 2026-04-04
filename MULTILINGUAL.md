# Language Support

Mask provides enterprise-grade PII detection for **English (en)** and **Spanish (es)**. The SDK is optimized specifically for these two languages across every tier of its detection pipeline.

## Supported Languages

| Language | Code | Support Level |
| :--- | :--- | :--- |
| 🇺🇸 **English** | `en` | ✅ Full — Default |
| 🇪🇸 **Spanish** | `es` | ✅ Full |

All other languages are not supported. Passing unsupported language codes will cause the SDK to fall back to English automatically.

---

## How It Works: The Waterfall

PII detection runs in three tiers, each optimized for EN/ES text.

### Tier 0: DLP Heuristic (Fastest)
The DLP engine scans for structural PII using locale-aware regex patterns and checksum validators.
- **Supported identity types:** US SSN, US EIN, US Passport, Spanish DNI/NIE, Credit Cards, IBAN, Crypto addresses, IBANs, and more.
- **Name patterns:** Honors English honorifics (Mr, Mrs, Dr, Prof) and Spanish honorifics (Sr, Sra, Srta).
- **Address patterns:** Matches US street addresses and Spanish street naming conventions (Calle, Avenida, Paseo, etc.).
- **Latency:** < 5ms.

### Tier 1: Deterministic (Global Standards)
Handles globally standardized formats like Emails, URLs, IP Addresses, and Credit Cards. These patterns are language-agnostic.
- **Latency:** < 2ms.

### Tier 2: Probabilistic NLP (Deep Context)
Uses Named Entity Recognition (NER) to catch context-dependent PII like Names, Organizations, and Locations.

**Python SDK:**
- Uses **Presidio + spaCy** with dedicated EN/ES models:
  - English: `en_core_web_lg` → `en_core_web_md` → `en_core_web_sm` (priority order)
  - Spanish: `es_core_news_lg` → `es_core_news_md` → `es_core_news_sm` (priority order)

**TypeScript SDK:**
- Uses **Transformers.js** with ONNX runtime.
  - English-only: `distilbert-base-uncased-ner-simple`
  - English + Spanish: `bert-base-multilingual-cased-ner-hrl`

---

## Configuration & Setup

### Environment Variables

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `MASK_LANGUAGES` | `string` | `en` | Comma-separated language codes. Supported values: `en`, `es`. |
| `MASK_NLP_TIMEOUT_SECONDS` | `int` | `30` / `60` | Max time to wait for Tier 2 NLP scan (30s TypeScript, 60s Python). |

### Setting variables

**In a `.env` file (Recommended):**
```env
MASK_LANGUAGES="en,es"
```

**In your Terminal:**
- **Bash/Zsh**: `export MASK_LANGUAGES="en,es"`
- **PowerShell**: `$env:MASK_LANGUAGES="en,es"`

**Directly in Code:**
- **Python**: `os.environ["MASK_LANGUAGES"] = "en,es"` (set before importing `mask_privacy`)
- **TypeScript**: `process.env.MASK_LANGUAGES = "en,es"` (set before initializing `MaskClient`)

### Python-Specific Options

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MASK_NLP_ENGINE` | `spacy` | Always `spacy` for EN/ES deployments. |
| `MASK_NLP_MAX_WORKERS` | `4` | Number of processes in the `ProcessPoolExecutor` for parallel NLP analysis. |

### TypeScript-Specific Options

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MASK_MODEL_CACHE_DIR` | `~/.cache` | Local directory for storing serialized ONNX models. |

---

## Technical Nuances

### Language Resolution
The `LanguageContextResolver` inspects the input text to determine `en` or `es`. For short strings (< 15 chars), it defaults to `en` unless strong Spanish markers are present. You can override explicitly:

**Python:**
```python
result = client.scan_and_tokenize(text, language="es")
```

**TypeScript:**
```ts
const result = await client.scanAndTokenize(text, { language: "es" });
```

### spaCy Model Matrix (Python)

| Language | Model Priority |
| :--- | :--- |
| **English** | `en_core_web_lg`, `en_core_web_md`, `en_core_web_sm` |
| **Spanish** | `es_core_news_lg`, `es_core_news_md`, `es_core_news_sm` |

---

## Air-Gapped & Offline Environments

### Python (Pre-install models)
```bash
pip install mask-privacy

# Download EN models
python -m spacy download en_core_web_sm

# Download ES models (optional, for Spanish support)
python -m spacy download es_core_news_sm

# Or use the CLI utility
mask cache-models --languages en,es --engine spacy
```

### TypeScript (Pre-cache models)
```bash
export MASK_MODEL_CACHE_DIR="./models"

# Trigger download for English
node -e "require('mask-privacy').getScanner().scanAndTokenize('John Doe')"

# Bundle the './models' folder with your application container
```

---

## Latency Benchmarks

*Measured on 4-vCPU 8GB RAM Instance (Standard Cloud VM)*

| Payload Size | Tier 0/1 (DLP) | Tier 2 (spaCy EN/ES) |
| :--- | :--- | :--- |
| **Short (1 sentence)** | < 1ms | ~40ms |
| **Standard (100 words)** | ~3ms | ~120ms |
| **Long (1000 words)** | ~12ms | ~600ms |

*For large documents, use `MASK_NLP_MAX_WORKERS` to parallelize processing or offload to a GPU-backed `RemoteScanner`.*
