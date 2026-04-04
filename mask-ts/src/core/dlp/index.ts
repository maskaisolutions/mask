/**
 * DLP (Data Loss Prevention) sub-package for Mask Privacy SDK.
 *
 * Provides multilingual entity detection, pattern-based classification,
 * hard-validation, and proximity-weighted confidence scoring that feeds
 * into the JIT / FPE encryption pipeline.
 */

export { LanguageContextResolver } from "./assessor";
export type { LanguageTag, LanguageBreakdown } from "./assessor";

export { DLPPatternRegistry, SensitiveCategory, LOCALE_NAME_RULES, LOCALE_ADDRESS_RULES } from "./registry";
export type { PatternDescriptor } from "./registry";

export { DLPValidationEngine } from "./handlers";
export {
  checkLuhn,
  checkSsnArea,
  checkIbanStructure,
  checkAbaRouting,
  checkVinFormat,
  checkBtcFormat,
  checkIpv4Octets,
} from "./handlers";

export { DLPConfidenceScorer } from "./scorer";
export type { ScorerConfig, ScoreInput } from "./scorer";
