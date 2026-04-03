/**
 * Entity Detection Scanner — Tiered Waterfall Pipeline.
 *
 * Scans unstructured text to identify PII (Emails, Phones, SSNs, Credit Cards,
 * Names) and replaces them in-place with Format-Preserving Encryption (FPE)
 * tokens.
 *
 * Detection Architecture (Waterfall):
 *   Tier 0 — DLP Heuristic: Multilingual, 50+ types, checksum validators
 *   Tier 1 — Deterministic: Regex + Checksum  (fast, provable, auditable)
 *   Tier 2 — Probabilistic: Local NLP via Transformers (catches names/orgs)
 */

import { config } from '../config';
import { encode } from './vault';
import { looksLikeToken } from './fpe_utils';
import { MaskNLPTimeout } from './exceptions';
import { LanguageContextResolver } from './dlp/assessor';
import { DLPPatternRegistry } from './dlp/registry';
import { DLPValidationEngine } from './dlp/handlers';
import { DLPConfidenceScorer } from './dlp/scorer';
import { Span, resolveOverlaps, reconstruct } from './span';

// Module-level DLP singletons (created once, reused for all scans)
const _dlpLanguageResolver = new LanguageContextResolver();
const _dlpPatternRegistry = new DLPPatternRegistry();
const _dlpValidationEngine = new DLPValidationEngine();
const _dlpConfidenceScorer = new DLPConfidenceScorer();

/** Regex patterns for Tier 1 deterministic detection */
export const REGEX_PATTERNS: Record<string, RegExp> = {
  "EMAIL_ADDRESS": /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g,
  "PHONE_NUMBER": /(?<!\d)(?:\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}|\d{3}[\s\-.]?\d{4})(?!\d)/g,
  "PHONE_NUMBER_INTL": /(?<!\d)\+(?:[1-9]\d{0,3})[-.\s]?\(?\d{1,5}\)?(?:[-.\s]?\d{2,4}){2,4}(?!\d)/g,
  "US_SSN": /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g,
  "CREDIT_CARD": /(?<!\d)(?:\d{4}[ \-]?){3}\d{4}(?!\d)/g,
  "US_ROUTING_NUMBER": /(?<!\d)\d{9}(?!\d)/g,
  "US_PASSPORT": /\b[A-Z]\d{8}\b/g,
  "DATE_OF_BIRTH": /\b(?:0[1-9]|1[0-2])\/(?:0[1-9]|[12]\d|3[01])\/(?:19|20)\d{2}\b|\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b/g,
};

/** Keywords whose presence boosts detection aggressiveness */
export const CONTEXT_KEYWORDS = new Set([
  "account number", "ssn", "phone", "credit card",
  "iban", "bank", "email", "pii", "personal info",
]);

export class BaseScanner {
  protected _supportedEntities: string[];

  constructor() {
    this._supportedEntities = [
      "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD",
      "US_BANK_NUMBER", "CRYPTO", "IBAN_CODE", "IP_ADDRESS", "PERSON",
    ];
  }

  setSupportedEntities(entities: string[]): void {
    this._supportedEntities = [...entities];
  }

  /** Validate a credit card number using the Luhn algorithm. */
  protected static _luhnChecksum(ccNumber: string): boolean {
    const digits = ccNumber.replace(/\D/g, "").split("").map(Number);
    let sum = 0;
    let shouldDouble = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = digits[i];
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }

  /** Validate a US ABA routing number using the checksum algorithm. */
  protected static _abaChecksum(routingNumber: string): boolean {
    const d = routingNumber.split("").map(Number);
    if (d.length !== 9) return false;
    const checksum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]);
    return checksum % 10 === 0;
  }

  protected async _tier0CollectSpans(
    text: string,
    confidenceThreshold: number,
  ): Promise<Span[]> {
    const detectedLanguage = _dlpLanguageResolver.resolve(text);
    const spans: Span[] = [];
    const categoryMap = _dlpPatternRegistry.getCategoryRegexesMap();

    // Pass 1: Category Mega-Regexes (O(text) per category bucket)
    for (const [catKey, { re, typeOrder }] of categoryMap.entries()) {
      const megaRe = new RegExp(re.source, re.flags);
      let m: RegExpExecArray | null;
      while ((m = megaRe.exec(text)) !== null) {
        // Identify which named group matched
        const groups = m.groups ?? {};
        let typeTag: string | undefined;
        for (const name of typeOrder) {
          if (groups[name] !== undefined) { typeTag = name; break; }
        }
        if (!typeTag) continue;
        const matchedStr = m[0];
        if (looksLikeToken(matchedStr)) continue;
        const descriptor = _dlpPatternRegistry.descriptorFor(typeTag);
        if (!descriptor) continue;

        const validatorResult = _dlpValidationEngine.run(descriptor.validatorTag, matchedStr);
        
        let conf: number;
        // FUZZY FAIL-SAFE logic
        if (validatorResult === false) {
          if (descriptor.isHighEntropy) {
            conf = 0.85; // Boosted to prioritize over generic types
          } else {
            continue;
          }
        } else {
          conf = _dlpConfidenceScorer.score({
            baseRisk: descriptor.baseRisk,
            matchStart: m.index,
            matchEnd: m.index + matchedStr.length,
            fullText: text,
            proximityTerms: descriptor.proximityTerms,
            validatorPassed: validatorResult,
          });
        }

        if (conf >= confidenceThreshold) {
          spans.push({ start: m.index, end: m.index + matchedStr.length,
            entityType: typeTag, originalValue: matchedStr,
            confidence: conf, method: 'dlp_heuristic', language: detectedLanguage });
        }
      }
    }

    // Pass 2: Locale-tuned name patterns (JIT)
    const nameProximity = new Set(['name', 'contact', 'person', 'nom', 'isim', '\u0627\u0633\u0645']);
    for (const nameRe of _dlpPatternRegistry.namePatternsFor(detectedLanguage)) {
      const re = new RegExp(nameRe.source, nameRe.flags);
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        if (looksLikeToken(m[0])) continue;
        const conf = _dlpConfidenceScorer.score({
          baseRisk: 0.50, matchStart: m.index, matchEnd: m.index + m[0].length,
          fullText: text, proximityTerms: nameProximity, validatorPassed: null,
        });
        if (conf >= confidenceThreshold) {
          spans.push({ start: m.index, end: m.index + m[0].length,
            entityType: 'PERSON_NAME', originalValue: m[0],
            confidence: conf, method: 'dlp_heuristic', language: detectedLanguage });
        }
      }
    }

    // Pass 3: Locale-tuned address patterns (JIT)
    for (const addrRe of _dlpPatternRegistry.addressPatternsFor(detectedLanguage)) {
      const re = new RegExp(addrRe.source, addrRe.flags);
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        if (looksLikeToken(m[0])) continue;
        spans.push({ start: m.index, end: m.index + m[0].length,
          entityType: 'PHYS_ADDRESS', originalValue: m[0],
          confidence: 0.55, method: 'dlp_heuristic', language: detectedLanguage });
      }
    }

    return spans;
  }

  /** Backward-compat wrapper — collects spans then single-pass encodes. */
  protected async _tier0Dlp(
    text: string,
    encodeFn: (val: string, options?: any) => Promise<string>,
    confidenceThreshold: number,
  ): Promise<[string, any[]]> {
    const spans = await this._tier0CollectSpans(text, confidenceThreshold);
    const resolved = resolveOverlaps(spans);
    const entities: any[] = [];
    await Promise.all(resolved.map(async (span) => {
      span.maskedValue = await encodeFn(span.originalValue, { entityType: span.entityType });
      entities.push({ type: span.entityType, value: span.originalValue,
        method: span.method, confidence: span.confidence,
        masked_value: span.maskedValue, language: span.language });
    }));
    return [reconstruct(text, resolved), entities];
  }

  protected async _tier1CollectSpans(
    text: string,
    boostEntities: Set<string>,
    aggressive: boolean,
    confidenceThreshold: number,
  ): Promise<Span[]> {
    const spans: Span[] = [];
    for (const [entityType, pattern] of Object.entries(REGEX_PATTERNS)) {
      const re = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(text)) !== null) {
        const val = match[0];
        if (looksLikeToken(val)) continue;
        let confidence = (aggressive || boostEntities.has(entityType.toLowerCase().replace(/_/g, ' '))) ? 1.0 : 0.95;
        if (entityType === 'CREDIT_CARD' && BaseScanner._luhnChecksum(val)) confidence = Math.max(confidence, 0.99);
        if (entityType === 'US_ROUTING_NUMBER' && !BaseScanner._abaChecksum(val)) continue;
        if (confidence >= confidenceThreshold) {
          spans.push({ start: match.index, end: match.index + val.length,
            entityType, originalValue: val, confidence, method: 'regex' });
        }
      }
    }
    return spans;
  }

  /** Backward-compat wrapper. */
  protected async _tier1Regex(
    text: string,
    encodeFn: (val: string, options?: any) => Promise<string>,
    boostEntities: Set<string>,
    aggressive: boolean,
    confidenceThreshold: number,
  ): Promise<[string, any[]]> {
    const spans = await this._tier1CollectSpans(text, boostEntities, aggressive, confidenceThreshold);
    const resolved = resolveOverlaps(spans);
    const entities: any[] = [];
    await Promise.all(resolved.map(async (span) => {
      span.maskedValue = await encodeFn(span.originalValue, { entityType: span.entityType });
      entities.push({ type: span.entityType, value: span.originalValue,
        method: span.method, confidence: span.confidence, masked_value: span.maskedValue });
    }));
    return [reconstruct(text, resolved), entities];
  }

  protected async _tier2Nlp(
    text: string,
    encodeFn: (val: string, options?: any) => Promise<string>,
    boostEntities: Set<string>,
    aggressive: boolean,
    confidenceThreshold: number,
  ): Promise<[string, any[]]> {
    return [text, []];
  }

  protected _resolveBoost(context?: string | null): Set<string> {
    if (!context) return new Set();
    const lowered = context.toLowerCase();
    const boosted = new Set<string>();
    for (const kw of CONTEXT_KEYWORDS) {
      if (lowered.includes(kw)) boosted.add(kw);
    }
    return boosted;
  }

  async scanAndTokenize(
    text: string,
    options: {
      encodeFn?: (val: string, options?: any) => Promise<string>;
      pipeline?: string[];
      confidenceThreshold?: number;
      context?: string | null;
      aggressive?: boolean;
    } = {}
  ): Promise<string> {
    if (!text || typeof text !== 'string') return text;

    const pipeline = options.pipeline || ['dlp', 'regex', 'checksum', 'nlp'];
    const _encode = options.encodeFn || encode;
    const confidenceThreshold = options.confidenceThreshold ?? 0.7;
    const boost = this._resolveBoost(options.context);

    // ── Span-accumulation phase (no string mutation) ─────────────────────
    const allSpans: Span[] = [];

    if (pipeline.includes('dlp')) {
      allSpans.push(...await this._tier0CollectSpans(text, confidenceThreshold));
    }
    if (pipeline.includes('regex') || pipeline.includes('checksum')) {
      allSpans.push(...await this._tier1CollectSpans(text, boost, !!options.aggressive, confidenceThreshold));
    }

    // ── Single-pass resolve + reconstruct ────────────────────────────────
    const resolved = resolveOverlaps(allSpans);
    await Promise.all(resolved.map(async (span) => {
      span.maskedValue = await _encode(span.originalValue, { entityType: span.entityType });
    }));
    let currentText = reconstruct(text, resolved);

    // ── Tier 2: Probabilistic NLP (on already-masked text) ───────────────
    if (pipeline.includes('nlp')) {
      [currentText] = await this._tier2Nlp(currentText, _encode, boost, !!options.aggressive, confidenceThreshold);
    }

    return currentText;
  }

  async scanAndReturnEntities(
    text: string,
    options: {
      encodeFn?: (val: string, options?: any) => Promise<string>;
      pipeline?: string[];
      confidenceThreshold?: number;
      context?: string | null;
      aggressive?: boolean;
    } = {}
  ): Promise<any[]> {
    if (!text || typeof text !== 'string') return [];

    const pipeline = options.pipeline || ['dlp', 'regex', 'checksum', 'nlp'];
    const _encode = options.encodeFn || encode;
    const confidenceThreshold = options.confidenceThreshold ?? 0.7;
    const boost = this._resolveBoost(options.context);
    const allEntities: any[] = [];

    // ── Span-accumulation phase ──────────────────────────────────────────
    const allSpans: Span[] = [];
    if (pipeline.includes('dlp')) {
      allSpans.push(...await this._tier0CollectSpans(text, confidenceThreshold));
    }
    if (pipeline.includes('regex') || pipeline.includes('checksum')) {
      allSpans.push(...await this._tier1CollectSpans(text, boost, !!options.aggressive, confidenceThreshold));
    }

    const resolved = resolveOverlaps(allSpans);
    await Promise.all(resolved.map(async (span) => {
      span.maskedValue = await _encode(span.originalValue, { entityType: span.entityType });
      allEntities.push({ type: span.entityType, value: span.originalValue,
        method: span.method, confidence: span.confidence,
        masked_value: span.maskedValue, language: span.language });
    }));

    const remaining = reconstruct(text, resolved);

    if (pipeline.includes('nlp')) {
      const [, tier2] = await this._tier2Nlp(remaining, _encode, boost, !!options.aggressive, confidenceThreshold);
      allEntities.push(...tier2);
    }

    return allEntities;
  }
}

/** @deprecated Use BaseScanner instead. Kept for backwards compatibility. */
export const PresidioScanner = BaseScanner;

// Singleton
let scannerInstance: BaseScanner | null = null;

export function getScanner(): BaseScanner {
  if (scannerInstance === null) {
    const scannerType = config.MASK_SCANNER_TYPE;
    
    if (scannerType === 'remote') {
      const { RemoteScanner } = require('./remote_scanner');
      scannerInstance = new RemoteScanner();
    } else {
      const { LocalTransformersScanner } = require('./transformers_scanner');
      scannerInstance = new LocalTransformersScanner();
    }
  }
  return scannerInstance as BaseScanner;
}

export function resetScanner(): void {
  if (scannerInstance && (scannerInstance as any).close) {
    (scannerInstance as any).close();
  }
  scannerInstance = null;
}
