# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.2.0]

### Added
- **KMS Keyring Proxying (PCI DSS):** Extended `BaseKeyProvider` to natively retrieve JSON Keyring documents straight from AWS KMS, Azure Key Vault, and HashiCorp Vault APIs, fully eliminating raw cryptographic secrets from persistent environment variables.
- **Bounded LRU Vault Cache:** Introduced a strict upper limit on caching overhead via `MASK_VAULT_MAX_MEMORY_KEYS` (default: 100,000). The `MemoryVault` mechanism was rearchitected to provide true LRU cache eviction, permanently resolving Out-Of-Memory (OOM) risks during massive dataset migrations.

### Changed
- **Asynchronous WAL Log Overflow (SOC 2):** Completely eliminated telemetry data loss under load. Replaced the blocking thread mechanisms (`_flushSync` DoS vulnerability) with an asynchronous Write-Ahead Log (WAL) that spools directly to disk overflowing buffers seamlessly.
- **Strict PII Telemetry Redaction:** Deprecated the usage of generic token regexing in the audit log pipelines (`_deep_mask`) for an absolute `is_unambiguously_safe_token()` check. This strictly enforces synthetic watermarks (`[TKN`, `tkn-`), permanently ensuring ambiguous PAN/SSN data will never accidentally bypass telemetry redaction.

## [3.5.1]

### Fixed
- **SDK Parity Synchronization:** Aligned the TypeScript SDK token generation schemas to inherently support Python's fixes. Added explicit string evaluations for `ES_ID` tags parsing Spanish Identifiers, and merged international prefix syntax blocks into `_PHONE_RE` to seamlessly mirror `generate_fpe_token` results.

## [3.5.0]

### Added
- **Spanish Identity Checksum Generation:** Expanded `generate_fpe_token` to accept matching criteria for `ES_ID` and `ES_DNI`, guaranteeing realistic, synthetic Spanish ID outputs with valid Mod-23 checksums.
- **International Dialer Resolution:** Included explicit international prefix tracking to `_PHONE_RE` (`^\+\d{2,3}[\s\-.]?\d{3}`) strictly to support `+34` native formatting for Spanish phone tokens.

### Changed
- **Python Async Deadlocks Fixed:** Offloaded heavy detection workloads (Tier 0 & Tier 1) in async methods directly into `asyncio.to_thread` pools to prevent long-running Mega-Regex passes from blocking the master event loop during NLP peaks.
- **TypeScript Promise Storm Mitigation:** Handled a V8 resource exhaustion vector by imposing an active `CHUNK_SIZE=50` limit on simultaneous asynchronous tokenization requests hitting the cryptography vault array.
- **Regex Compiler Flag Sandbox:** Fully partitioned `DLPPatternRegistry` compilation into distinct Case-Sensitive and Case-Insensitive fallback buckets, resolving a dangerous compiler bleeding edge-case where a single `(?i)` flag would unilaterally override strict checksum validations across the entire category grouping. 

### Fixed
- **Python Async Data Corruption:** Hotfixed an index calculation mismatch inside `ascan_and_tokenize` where right-to-left pointer updates failed to mutate original index lists, directly leading to incorrectly segmented synthetic tokens.
- **Locale Handoff Drift:** Locked down native language detection immediately to the top of the event chain to resolve downstream NLP classification errors introduced post-tokenization. 
- **Substring Boost Invalidation:** Re-configured the Context Proximity scoring matrices (`_resolve_boost`) using strict Regex `\b` word boundary logic, resolving aggressive false-positives triggered on internal string containment (e.g. "id" boosting adjacent triggers while naturally inside the word "provider").

## [3.4.0]

### Added
- **2-Tier Model-Augmented Waterfall:** Optimized the detection pipeline into a primary High-Precision Deterministic Tier (Registry + Checksums) and a secondary Probabilistic Neural Tier (PERSON, LOCATION, ORGANIZATION).
- **Unified DLP Registry:** Consolidated over 50+ sensitive data signatures (Financial, Identity, Contact, Health) into a single, shared source of truth between Python and TypeScript.
- **Deep Spanish PII Support:** Production-grade detection for Spanish Social Security (NUSS), Bank Accounts (CCC), and Identity (DNI/NIE) with full checksum verification (Mod-97/Mod-11) and Proximity Context Boosting.
- **Fail-Shut Security Strategy:** Default `MASK_FAIL_STRATEGY=closed` to prevent PII leakage when vault infrastructure is unreachable.

### Changed
- **Architectural Waterfall:** Simplified the detection pipeline by consolidating "Tier 1" regex into "Tier 0" DLP, reducing redundant compute and preventing entity collisions.
- **NLP Entity Standardization:** Neural tier is now strictly standardized to `["PERSON", "LOCATION", "ORGANIZATION"]` across all SDKs to ensure functional parity.
- **Tiered Mutation:** All deterministic patterns are now matched and masked *before* neural fuzzy logic runs, improving performance by up to 30% for high-density PII text.

### Fixed
- **Logic Drift:** Eliminated inconsistencies between Python and TypeScript detection results by utilizing the shared DLP Registry.
- **Token Lifecycle:** Fixed race conditions in async tokenization for parallel tool calls.

---

[4.2.0]: https://github.com/mask-ai-solutions/mask/releases/tag/v4.2.0
[3.5.1]: https://github.com/mask-ai-solutions/mask/releases/tag/v3.5.1
[3.5.0]: https://github.com/mask-ai-solutions/mask/releases/tag/v3.5.0
[3.4.0]: https://github.com/mask-ai-solutions/mask/releases/tag/v3.4.0
