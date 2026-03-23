/**
 * Entity Detection Scanner — Tiered Waterfall Pipeline.
 *
 * Scans unstructured text to identify PII (Emails, Phones, SSNs, Credit Cards,
 * Names) and replaces them in-place with Format-Preserving Encryption (FPE)
 * tokens.
 *
 * Detection Architecture (Waterfall):
 *   Tier 1 — Deterministic: Regex + Checksum  (fast, provable, auditable)
 *   Tier 2 — Probabilistic: Local NLP via Transformers (catches names/orgs)
 */

import * as process from 'process';
import { encode } from './vault';
import { looksLikeToken } from './fpe_utils';
import { MaskNLPTimeout } from './exceptions';

/** Regex patterns for Tier 1 deterministic detection */
export const REGEX_PATTERNS: Record<string, RegExp> = {
  "EMAIL_ADDRESS": /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g,
  "PHONE_NUMBER": /\+?1?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}|\d{3}[\s\-.]?\d{4}/g,
  "PHONE_NUMBER_INTL": /\+(?:44|33|49)[\s\-.]?\(?\d{1,5}\)?(?:[\s\-.]?\d{2,4}){2,4}/g,
  "US_SSN": /\d{3}-\d{2}-\d{4}/g,
  "CREDIT_CARD": /(?:\d{4}[ \-]?){3}\d{4}/g,
  "US_ROUTING_NUMBER": /\b\d{9}\b/g,
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

  protected async _tier1Regex(
    text: string,
    encodeFn: (val: string) => Promise<string>,
    boostEntities: Set<string>,
    aggressive: boolean,
    confidenceThreshold: number,
  ): Promise<[string, any[]]> {
    let entities: any[] = [];
    let excised = text;

    let allMatches: any[] = [];

    for (const [entityType, pattern] of Object.entries(REGEX_PATTERNS)) {
      // Create a fresh regex for matchAll
      const re = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = re.exec(text)) !== null) {
        let confidence = 0.95;
        if (aggressive || boostEntities.has(entityType.toLowerCase().replace(/_/g, " "))) {
          confidence = 1.0;
        }
        if (entityType === "CREDIT_CARD" && BaseScanner._luhnChecksum(match[0])) {
          confidence = Math.max(confidence, 0.99);
        }
        if (entityType === "US_ROUTING_NUMBER" && !BaseScanner._abaChecksum(match[0])) {
          continue;
        }
        allMatches.push({
          start: match.index,
          end: match.index + match[0].length,
          type: entityType,
          value: match[0],
          confidence
        });
      }
    }

    // Deduplicate overlapping spans — keep the longest match
    allMatches.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    let filtered: any[] = [];
    let lastEnd = -1;
    for (const m of allMatches) {
      if (m.start >= lastEnd) {
        filtered.push(m);
        lastEnd = m.end;
      }
    }

    // Replace from right to left to preserve offsets
    const sortedFiltered = [...filtered].sort((a, b) => b.start - a.start);
    for (const m of sortedFiltered) {
      if (m.confidence >= confidenceThreshold && !looksLikeToken(m.value)) {
        const token = await encodeFn(m.value);
        excised = excised.slice(0, m.start) + token + excised.slice(m.end);
        entities.push({
          type: m.type,
          value: m.value,
          method: "regex",
          confidence: m.confidence,
          masked_value: token,
        });
      }
    }

    return [excised, entities];
  }

  protected async _tier2Nlp(
    text: string,
    encodeFn: (val: string) => Promise<string>,
    boostEntities: Set<string>,
    aggressive: boolean,
    confidenceThreshold: number,
  ): Promise<[string, any[]]> {
    /**
     * Base implementation is a no-op. Override in LocalTransformersScanner
     * to enable NLP-based detection.
     */
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
      encodeFn?: (val: string) => Promise<string>;
      pipeline?: string[];
      confidenceThreshold?: number;
      context?: string | null;
      aggressive?: boolean;
    } = {}
  ): Promise<string> {
    if (!text || typeof text !== 'string') return text;

    const pipeline = options.pipeline || ["regex", "checksum", "nlp"];
    const _encode = options.encodeFn || encode;
    const confidenceThreshold = options.confidenceThreshold ?? 0.7;
    const boost = this._resolveBoost(options.context);

    let currentText = text;

    if (pipeline.includes("regex") || pipeline.includes("checksum")) {
      [currentText] = await this._tier1Regex(currentText, _encode, boost, !!options.aggressive, confidenceThreshold);
    }

    if (pipeline.includes("nlp")) {
      [currentText] = await this._tier2Nlp(currentText, _encode, boost, !!options.aggressive, confidenceThreshold);
    }

    return currentText;
  }

  async scanAndReturnEntities(
    text: string,
    options: {
      encodeFn?: (val: string) => Promise<string>;
      pipeline?: string[];
      confidenceThreshold?: number;
      context?: string | null;
      aggressive?: boolean;
    } = {}
  ): Promise<any[]> {
    if (!text || typeof text !== 'string') return [];

    const pipeline = options.pipeline || ["regex", "checksum", "nlp"];
    const _encode = options.encodeFn || encode;
    const confidenceThreshold = options.confidenceThreshold ?? 0.7;
    const boost = this._resolveBoost(options.context);
    let allEntities: any[] = [];
    let remaining = text;

    if (pipeline.includes("regex") || pipeline.includes("checksum")) {
      const [newText, tier1] = await this._tier1Regex(remaining, _encode, boost, !!options.aggressive, confidenceThreshold);
      remaining = newText;
      allEntities.push(...tier1);
    }

    if (pipeline.includes("nlp")) {
      const [_newText, tier2] = await this._tier2Nlp(remaining, _encode, boost, !!options.aggressive, confidenceThreshold);
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
    const scannerType = process.env.MASK_SCANNER_TYPE?.toLowerCase() || 'local';
    
    if (scannerType === 'remote') {
      const { RemoteScanner } = require('./remote_scanner');
      scannerInstance = new RemoteScanner();
    } else {
      // Use the local Transformers-based scanner by default for full NLP support
      const { LocalTransformersScanner } = require('./transformers_scanner');
      scannerInstance = new LocalTransformersScanner();
    }
  }
  return scannerInstance as BaseScanner;
}
