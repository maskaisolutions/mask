/**
 * DLP Confidence Scorer — Proximity-weighted scoring for sensitive data matches.
 *
 * Combines three independent signals into a single confidence value:
 * 1. Base risk — intrinsic leakage probability of the data type.
 * 2. Proximity boost — logarithmic-decay bonus for each context keyword
 *    found near the match within a configurable window.
 * 3. Validator override — hard-validator pass forces confidence to 0.99.
 *
 * The scorer is stateless and safe for concurrent use.
 */

export interface ScorerConfig {
  contextWindow?: number;
  keywordBoost?: number;
  validatorOverride?: number;
  maxConfidence?: number;
  penaltyFactor?: number;
}

const DEFAULT_CONFIG: Required<ScorerConfig> = {
  contextWindow: 100,
  keywordBoost: 0.10,
  validatorOverride: 0.99,
  maxConfidence: 0.99,
  penaltyFactor: 0.99, // Renamed functionally to validator failure penalty subtraction
};

export interface ScoreInput {
  baseRisk: number;
  matchStart: number;
  matchEnd: number;
  fullText: string;
  proximityTerms: ReadonlySet<string>;
  validatorPassed: boolean | null;
}

/**
 * Calculate a weighted confidence score for a single regex hit.
 *
 * @example
 * ```ts
 * const scorer = new DLPConfidenceScorer();
 * const score = scorer.score({
 *   baseRisk: 0.92,
 *   matchStart: 10,
 *   matchEnd: 21,
 *   fullText: "TC Kimlik No: 10000000146",
 *   proximityTerms: new Set(["kimlik", "tc"]),
 *   validatorPassed: true,
 * });
 * // score === 0.99 (validator override)
 * ```
 */
export class DLPConfidenceScorer {
  private readonly window: number;
  private readonly kwBoost: number;
  private readonly valOverride: number;
  private readonly ceil: number;
  private readonly penalty: number;

  constructor(overrides: ScorerConfig = {}) {
    const cfg = { ...DEFAULT_CONFIG, ...overrides };
    this.window = cfg.contextWindow;
    this.kwBoost = cfg.keywordBoost;
    this.valOverride = cfg.validatorOverride;
    this.ceil = cfg.maxConfidence;
    this.penalty = cfg.penaltyFactor;
  }

  /**
   * Compute the final confidence for one candidate match.
   *
   * @returns Confidence in [0.0, maxConfidence].
   */
  score(input: ScoreInput): number {
    // Hard-validator short-circuits
    if (input.validatorPassed === true) return this.valOverride;
    if (input.validatorPassed === false) {
      return Math.max(0.0, input.baseRisk - this.penalty);
    }

    // Extract the context window around the match
    const windowLo = Math.max(0, input.matchStart - this.window);
    const windowHi = Math.min(input.fullText.length, input.matchEnd + this.window);
    const contextSlice = input.fullText.slice(windowLo, windowHi).toLowerCase();

    // Accumulate proximity bonuses
    let proximityBonus = 0.0;
    const matchMid = (input.matchStart + input.matchEnd) / 2.0;

    for (const term of input.proximityTerms) {
      let searchPos = 0;
      while (true) {
        const idx = contextSlice.indexOf(term, searchPos);
        if (idx === -1) break;
        // Translate window-relative index back to absolute offset
        const absPos = windowLo + idx;
        const distance = Math.abs(absPos - matchMid);
        const bonus = this.kwBoost / (1.0 + Math.log(1.0 + distance));
        proximityBonus += bonus;
        searchPos = idx + term.length;
      }
    }

    const raw = input.baseRisk + proximityBonus;
    return Math.min(this.ceil, raw);
  }
}
