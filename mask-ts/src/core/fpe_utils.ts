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
  "|\\+[1-9]\\d{0,3}-555-\\d{7}" +                                 // Phone
  "|\\d{3}-\\d{2}-\\d{4}" +                                        // SSN
  "|\\d{4}-\\d{4}-\\d{4}-\\d{4}" +                                 // CC
  "|\\b\\d{9}\\b" +                                                // Routing
  "|\\b000\\d{5}[A-Z]\\b" +                                        // Spanish DNI token
  "|[A-Z]{2}00[A-F0-9]{4,16}" +                                    // IBAN token
  "|<(?:PER|LOC|ORG):[^>]+>" +                                     // NLP Semantic tokens V4
  "|\\b[A-Z][a-zA-Z, ]+-[0-9]{3,10}\\b" +                          // Bijective Name/Loc
  "|\\[TKN-[^\\]]+\\]",                                            // Opaque
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

  // SSN tokens: XXX-XX-XXXX
  if (/^\d{3}-\d{2}-\d{4}$/.test(v)) {
    return true;
  }

  // Credit card tokens: XXXX-XXXX-XXXX-XXXX
  if (/^\d{4}-\d{4}-\d{4}-\d{4}$/.test(v)) {
    return true;
  }

  // Routing tokens: XXXXXXXXX
  if (v.length === 9 && /^\d+$/.test(v)) {
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
  
  // Bijective Name: Word Word-1234
  if (v.includes("-") && v.length >= 6) {
    const parts = v.split("-");
    const tag = parts[parts.length - 1];
    if (tag.length >= 3 && tag.length <= 10 && /^\d+$/.test(tag)) {
        return true;
    }
  }

  return false;
}

/**
 * Strict token check safe for use inside audit log redaction (_deepMask).
 *
 * Unlike looksLikeToken(), this function excludes patterns that are AMBIGUOUS
 * with real sensitive data (raw Credit Card and SSN formats). It only returns
 * true when the value carries an unambiguous FPE watermark that real PII
 * cannot share.
 *
 * This prevents real PANs / SSNs from bypassing redaction and being written
 * to SOC 2 / HIPAA audit logs in plaintext — a PCI DSS Level 1 failure.
 */
export function isUnambiguouslySafeToken(value: string | any): boolean {
  if (typeof value !== 'string') return false;
  const v = value.trim();

  // Email FPE token: tkn-<hex>@domain.tld
  if (v.startsWith("tkn-") && v.includes("@")) {
    const parts = v.split("@");
    if (parts.length === 2 && parts[0].length >= 12 && parts[1].includes(".")) {
      return true;
    }
  }

  // Phone FPE token: +CC-555-XXXXXXX  (555 exchange is synthetic watermark)
  if (/^\+[1-9]\d{0,3}-555-\d{7}$/.test(v)) return true;

  // Spanish DNI FPE token: always starts 000 (real DNIs never start 000)
  if (/^000\d{5}[A-Z]$/.test(v)) return true;

  // IBAN FPE token: XX00... (real IBANs never have 00 as check digits)
  if (/^[A-Z]{2}00[A-F0-9]{4,16}$/.test(v)) return true;

  // Semantic NLP tokens: <PER:...>, <LOC:...>, <ORG:...>
  if (/^<(PER|LOC|ORG):[^>]+>$/.test(v)) return true;

  // Opaque fallback tokens: [TKN-...]
  if (v.startsWith("[TKN-") && v.endsWith("]")) return true;

  // Bijective Name/Location tokens: end with synthetic numeric tag
  if (/^[A-Z][a-zA-Z, ]+-[0-9]{3,10}$/.test(v)) return true;

  // NOTE: Raw SSN (\d{3}-\d{2}-\d{4}), CC (\d{4}-\d{4}-\d{4}-\d{4}),
  // and routing (\d{9}) patterns are intentionally EXCLUDED because real
  // PII shares these exact formats. Use looksLikeToken() only for
  // detokenization (where context guarantees a token is present).
  return false;
}
