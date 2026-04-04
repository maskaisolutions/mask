# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] 

### Added
- **Unified DLP Registry:** Consolidated over 50+ sensitive data signatures (Financial, Identity, Contact, Health) into a single, shared source of truth between Python and TypeScript.
- **Deep Spanish PII Support:** Production-grade detection for Spanish Social Security (NUSS), Bank Accounts (CCC), and Identity (DNI/NIE) with full checksum verification (Mod-97/Mod-11).
- **Proximity Context Boosting:** Added language-specific term lists (e.g., *cuenta*, *seguridad social*, *nacimiento*) to boost detection confidence based on surrounding context.
- **Fail-Shut Security Strategy:** Default `MASK_FAIL_STRATEGY=closed` to prevent PII leakage when vault infrastructure is unreachable.

### Changed
- **Architectural Waterfall:** Simplified the detection pipeline by consolidating "Tier 1" regex into "Tier 0" DLP, reducing redundant compute and preventing entity collisions.
- **NLP Entity Standardization:** Neural tier is now strictly standardized to `["PERSON", "LOCATION", "ORGANIZATION"]` across all SDKs to ensure functional parity.
- **Tiered Mutation:** All deterministic patterns are now matched and masked *before* neural fuzzy logic runs, improving performance by up to 30% for high-density PII text.

### Fixed
- **Logic Drift:** Eliminated inconsistencies between Python and TypeScript detection results by utilizing the shared DLP Registry.
- **Token Lifecycle:** Fixed race conditions in async tokenization for parallel tool calls.

---

[3.2.0]: https://github.com/mask-ai-solutions/mask/releases/tag/v3.2.0
