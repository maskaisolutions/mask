/**
 * Format-Preserving Encryption (FPE) utilities.
 *
 * Contains non-cryptographic helpers to identify and match tokens.
 * Separated to avoid circular dependencies in the SDK.
 */

/**
 * Regex that matches ANY valid Mask token.
 * Used for sub-string detokenization (finding tokens inside paragraphs).
 */
export const TOKEN_PATTERN = new RegExp(
  "tkn-[a-f0-9]{8,64}@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}" +            // Email
  "|\\+[1-9]\\d{0,3}-555-\\d{7}" +                           // Phone
  "|000-00-\\d{4}" +                            // SSN
  "|4000-0000-0000-\\d{4}" +                    // CC
  "|000000\\d{3}" +                             // Routing
  "|000\\d{5}[A-Z]" +                           // Spanish DNI token
  "|[A-Z]{2}00[A-F0-9]{4,16}" +                // IBAN token
  "|<(?:PER|LOC|ORG):[^>]+>" +                 // NLP Semantic tokens
  "|\\[TKN-[a-f0-9]{8,64}\\]",                  // Opaque
  "g"
);

/**
 * Heuristic: return true if value appears to be a Mask token.
 */
export function looksLikeToken(value: string | any): boolean {
  if (typeof value !== 'string') return false;
  const v = value.trim();

  // Email tokens: tkn-<hex>@domain.com
  if (v.startsWith("tkn-") && v.includes("@")) {
    const parts = v.split("@");
    if (parts.length === 2 && parts[0].length >= 12 && parts[1].includes(".")) {
      return true;
    }
  }

  // Phone tokens: +CC-555-XXXXXXX
  if (/^\+[1-9]\d{0,3}-555-\d{7}$/.test(v)) {
    return true;
  }

  // SSN tokens: 000-00-XXXX
  if (v.startsWith("000-00-") && v.length === 11) {
    return true;
  }

  // Credit card tokens: 4000-0000-0000-XXXX
  if (v.startsWith("4000-0000-0000-") && v.length === 19) {
    return true;
  }

  // Routing tokens: 000000XXX
  if (v.startsWith("000000") && v.length === 9) {
    return true;
  }



  // Spanish ID tokens: 000XXXXX[A-Z]
  if (v.length === 9 && v.startsWith("000") && /[A-Z]$/.test(v)) {
    return true;
  }

  // IBAN tokens: XX00... (zero check digits indicate synthetic)
  if (/^[A-Z]{2}00[A-F0-9]{4,16}$/.test(v)) {
    return true;
  }

  // Semantic NLP tokens: <PER:Taylor_Morgan>
  if (/^<(PER|LOC|ORG):[^>]+>$/.test(v)) {
    return true;
  }

  // Opaque fallback tokens: [TKN-<hex>]
  if (v.startsWith("[TKN-") && v.endsWith("]")) {
    return true;
  }

  return false;
}


