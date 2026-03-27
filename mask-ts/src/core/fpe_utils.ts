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
  "tkn-[a-f0-9]{8,64}@email\\.com" +            // Email
  "|\\+1-555-\\d{7}" +                           // Phone
  "|000-00-\\d{4}" +                            // SSN
  "|4000-0000-0000-\\d{4}" +                    // CC
  "|000000\\d{3}" +                             // Routing
  "|990000\\d{4}[02468]" +                      // Turkish TCID token
  "|100000\\d{4}" +                             // Saudi NID token
  "|784-0000-\\d{7}-\\d" +                       // UAE EID token
  "|[A-Z]{2}00[A-F0-9]{4,16}" +                // IBAN token
  "|\\[TKN-[a-f0-9]{8,64}\\]",                  // Opaque
  "g"
);

/**
 * Heuristic: return true if value appears to be a Mask token.
 */
export function looksLikeToken(value: string | any): boolean {
  if (typeof value !== 'string') return false;
  const v = value.trim();

  // Email tokens: tkn-<hex>@email.com
  if (v.startsWith("tkn-") && v.includes("@email.com")) {
    return true;
  }

  // Phone tokens: +1-555-XXXXXXX
  if (v.startsWith("+1-555-") && v.length === 14) {
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

  // UAE Emirates ID tokens: 784-0000-XXXXXXX-X
  if (v.startsWith("784-0000-") && v.length === 18) {
    return true;
  }

  // Turkish TCID tokens: 990000XXXX(even)
  if (v.length === 11 && v.startsWith("990000") && /^\d+$/.test(v) && parseInt(v[v.length - 1], 10) % 2 === 0) {
    return true;
  }

  // Saudi NID tokens: 100000XXXX
  if (v.length === 10 && v.startsWith("100000") && /^\d+$/.test(v)) {
    return true;
  }

  // IBAN tokens: XX00... (zero check digits indicate synthetic)
  if (/^[A-Z]{2}00[A-F0-9]{4,16}$/.test(v)) {
    return true;
  }

  // Opaque fallback tokens: [TKN-<hex>]
  if (v.startsWith("[TKN-") && v.endsWith("]")) {
    return true;
  }

  return false;
}

