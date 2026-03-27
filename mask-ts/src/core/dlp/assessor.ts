/**
 * Language Context Resolver — Unicode-block heuristic for multilingual DLP.
 *
 * Examines the character distribution of an input buffer to infer the
 * dominant script / language.  The resolved language tag is consumed by
 * the DLPPatternRegistry to prioritise locale-specific regex groups.
 *
 * Supported language tags:
 *   en — English (default / Latin-only fallback)
 *   es — Spanish
 *   fr — French
 *   de — German
 *   tr — Turkish
 *   ar — Arabic
 *   zh — Chinese
 *   ja — Japanese
 */

export type LanguageTag =
  | "en" | "es" | "fr" | "de" | "tr" | "ar" | "zh" | "ja";

/**
 * Ordered array of script signatures — more specific blocks are checked first
 * to avoid misclassification (e.g. ş/ğ/ı for Turkish before generic accented-Latin).
 */
const SCRIPT_SIGNATURES: ReadonlyArray<{ tag: LanguageTag; pattern: RegExp }> = [
  // CJK / East-Asian — checked first because they are unambiguous
  { tag: "zh", pattern: /[\u4e00-\u9fff\u3400-\u4dbf]/g },
  { tag: "ja", pattern: /[\u3040-\u309f\u30a0-\u30ff\u31f0-\u31ff]/g },

  // Arabic script — covers Standard Arabic, Urdu overlap, etc.
  { tag: "ar", pattern: /[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff\ufb50-\ufdff\ufe70-\ufeff]/g },

  // Turkish — distinguished by dotless-i (ı), soft-g (ğ), ş, and cedilla ç
  { tag: "tr", pattern: /[ğıİşŞ]/g },

  // German — umlauts and Eszett
  { tag: "de", pattern: /[äöüÄÖÜß]/g },

  // Spanish — ñ and inverted punctuation
  { tag: "es", pattern: /[ñÑ¡¿]/g },

  // French — cedilla, accented vowels with circumflex / diaeresis
  { tag: "fr", pattern: /[àâçéèêëïîôùûüÿœæ]/gi },
];

export interface LanguageBreakdown {
  language: LanguageTag;
  breakdown: Record<string, number>;
}

/**
 * Determine the dominant language of a text buffer.
 *
 * The resolver is stateless and safe for concurrent use.
 *
 * @example
 * ```ts
 * const resolver = new LanguageContextResolver();
 * const tag = resolver.resolve("Merhaba, TC Kimlik Numaram 12345678901");
 * // tag === "tr"
 * ```
 */
export class LanguageContextResolver {
  /** Minimum number of script-specific characters required. */
  private readonly charThreshold: number;

  constructor(charThreshold: number = 1) {
    this.charThreshold = charThreshold;
  }

  /** Return an ISO-639-1 language tag for the given text. Falls back to "en". */
  resolve(text: string): LanguageTag {
    if (!text) return "en";

    for (const { tag, pattern } of SCRIPT_SIGNATURES) {
      // Reset the regex lastIndex for global patterns
      pattern.lastIndex = 0;
      const hits = text.match(pattern);
      if (hits && hits.length >= this.charThreshold) {
        return tag;
      }
    }
    return "en";
  }

  /** Return the language tag together with per-script hit counts. */
  resolveWithDetail(text: string): LanguageBreakdown {
    const breakdown: Record<string, number> = {};

    for (const { tag, pattern } of SCRIPT_SIGNATURES) {
      pattern.lastIndex = 0;
      const hits = text.match(pattern);
      if (hits && hits.length > 0) {
        breakdown[tag] = hits.length;
      }
    }

    let resolved: LanguageTag = "en";
    for (const { tag } of SCRIPT_SIGNATURES) {
      if ((breakdown[tag] ?? 0) >= this.charThreshold) {
        resolved = tag;
        break;
      }
    }

    return { language: resolved, breakdown };
  }
}
