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

/**
 * Runs an async callback over an array in sequential batches of CHUNK_SIZE.
 *
 * This prevents unbounded Promise.all storms on large documents (e.g. a file
 * with 10,000+ PII hits would previously flood the vault/crypto subsystem with
 * 10,000 concurrent promises). With chunking we cap concurrency at 50 at a
 * time, balancing throughput and memory/latency stability.
 */
const CHUNK_SIZE = 50;
async function chunkEncode<T>(items: T[], fn: (item: T) => Promise<void>): Promise<void> {
  for (let i = 0; i < items.length; i += CHUNK_SIZE) {
    await Promise.all(items.slice(i, i + CHUNK_SIZE).map(fn));
  }
}

export class BaseScanner {
  protected _supportedEntities: string[];

  constructor() {
    this._supportedEntities = [
      "PERSON", "LOCATION", "ORGANIZATION",
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
    // getCategoryRegexesMap now returns Map<catKey, {re, typeOrder}[]>
    // Each category has at most two sub-groups: one case-sensitive, one case-insensitive.
    // Keeping them separate prevents IGNORECASE from bleeding between patterns.
    const categoryMap = _dlpPatternRegistry.getCategoryRegexesMap();

    // Pass 1: Category sub-group regexes (O(text) per sub-group)
    for (const [catKey, groups] of categoryMap.entries()) {
      for (const { re, typeOrder } of groups) {
        const megaRe = new RegExp(re.source, re.flags);
        let m: RegExpExecArray | null;
        while ((m = megaRe.exec(text)) !== null) {
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

  /** Tier 1 — Deterministic detection (Legacy: Redirected to DLP) */
  protected async _tier1CollectSpans(
    text: string,
    boostEntities: Set<string>,
    aggressive: boolean,
    confidenceThreshold: number,
  ): Promise<Span[]> {
    return this._tier0CollectSpans(text, confidenceThreshold);
  }

  /** Backward-compat wrapper. Redirected to DLP. */
  protected async _tier1Regex(
    text: string,
    encodeFn: (val: string, options?: any) => Promise<string>,
    boostEntities: Set<string>,
    aggressive: boolean,
    confidenceThreshold: number,
  ): Promise<[string, any[]]> {
    return this._tier0Dlp(text, encodeFn, confidenceThreshold);
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
    const boosted = new Set<string>();
    // Match proximity terms on whole-word boundaries only to prevent short
    // terms (e.g. "id") from firing inside unrelated words ("hidden", "video").
    for (const [, desc] of _dlpPatternRegistry.iterDescriptors()) {
      for (const term of desc.proximityTerms) {
        const pattern = new RegExp('\\b' + term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i');
        if (pattern.test(context)) {
          boosted.add(desc.category.toLowerCase());
          break;
        }
      }
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

    const pipeline = options.pipeline || ['dlp', 'nlp'];
    const _encode = options.encodeFn || encode;
    const confidenceThreshold = options.confidenceThreshold ?? 0.7;
    const boost = this._resolveBoost(options.context);

    // ── Span-accumulation phase (no string mutation) ─────────────────────
    const allSpans: Span[] = [];

    if (pipeline.includes('dlp') || pipeline.includes('regex') || pipeline.includes('checksum')) {
      allSpans.push(...await this._tier0CollectSpans(text, confidenceThreshold));
    }

    // ── Single-pass resolve + reconstruct (with chunked encoding) ────────
    const resolved = resolveOverlaps(allSpans);
    await chunkEncode(resolved, async (span) => {
      span.maskedValue = await _encode(span.originalValue, { entityType: span.entityType });
    });
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

    const pipeline = options.pipeline || ['dlp', 'nlp'];
    const _encode = options.encodeFn || encode;
    const confidenceThreshold = options.confidenceThreshold ?? 0.7;
    const boost = this._resolveBoost(options.context);
    const allEntities: any[] = [];

    // ── Span-accumulation phase ──────────────────────────────────────────
    const allSpans: Span[] = [];
    if (pipeline.includes('dlp') || pipeline.includes('regex') || pipeline.includes('checksum')) {
      allSpans.push(...await this._tier0CollectSpans(text, confidenceThreshold));
    }

    const resolved = resolveOverlaps(allSpans);
    await chunkEncode(resolved, async (span) => {
      span.maskedValue = await _encode(span.originalValue, { entityType: span.entityType });
      allEntities.push({ type: span.entityType, value: span.originalValue,
        method: span.method, confidence: span.confidence,
        masked_value: span.maskedValue, language: span.language });
    });

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
