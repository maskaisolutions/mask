/**
 * Span Resolution Engine — Sweep-Line Overlap Resolver (TypeScript).
 *
 * All detection tiers now return Span objects instead of mutating the text.
 * resolveOverlaps() chooses the winning span in every conflicting region,
 * and reconstruct() rebuilds the string exactly once.
 */

export interface Span {
  start: number;
  end: number;
  entityType: string;
  originalValue: string;
  confidence: number;
  method: string;      // "dlp_heuristic" | "regex" | "nlp"
  language?: string;
  // Audit trail fields (DSPM compliance)
  ruleId?: string;                 // e.g. "MASK-FIN-001"
  complianceScope?: ReadonlySet<string>;  // e.g. {"PCI-DSS", "HIPAA"}
  maskedValue?: string;
}

/**
 * Return a non-overlapping, right-to-left-ordered subset of spans.
 *
 * Algorithm:
 * 1. Sort by start ASC, length DESC (prefer longer), confidence DESC.
 * 2. Walk left-to-right tracking occupiedEnd.
 * 3. Fully-contained spans are discarded.
 * 4. Partial overlaps resolve by confidence (higher wins).
 */
export function resolveOverlaps(spans: Span[]): Span[] {
  if (spans.length === 0) return [];

  const sorted = [...spans].sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    const lenDiff = (b.end - b.start) - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return b.confidence - a.confidence;
  });

  const resolved: Span[] = [];
  let occupiedEnd = -1;

  for (const span of sorted) {
    if (span.start >= occupiedEnd) {
      resolved.push(span);
      occupiedEnd = span.end;
    } else if (span.end <= occupiedEnd) {
      // Fully inside an already-accepted span — discard.
      continue;
    } else {
      // Partial overlap — keep highest confidence.
      const last = resolved[resolved.length - 1];
      if (span.confidence > last.confidence) {
        resolved.pop();
        resolved.push(span);
        occupiedEnd = span.end;
      }
    }
  }

  // Return descending start order for right-to-left reconstruction.
  return resolved.sort((a, b) => b.start - a.start);
}

/**
 * Rebuild text from a right-to-left-ordered list of resolved spans.
 * Each span must have maskedValue populated.
 * This is the single string-construction pass that replaces all slice loops.
 */
export function reconstruct(text: string, resolvedSpans: Span[]): string {
  let result = text;
  for (const span of resolvedSpans) {
    if (span.maskedValue == null) continue;
    result = result.slice(0, span.start) + span.maskedValue + result.slice(span.end);
  }
  return result;
}
