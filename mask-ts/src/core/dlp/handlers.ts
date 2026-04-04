/**
 * DLP Validation Engine — Hard-validators for post-match verification.
 *
 * Each validator implements a deterministic check (checksum, length rule,
 * character constraint) that confirms whether a regex-matched string is
 * genuinely sensitive data.  Passing a hard-validator overrides the
 * confidence score to 0.99 ("Definitive").
 *
 * All functions are pure and stateless, making the module safe for
 * concurrent use.
 */

// ── Luhn (Mod-10) — Credit Cards, UAE Emirates ID ──────────────────────────

export function checkLuhn(raw: string): boolean {
  const stripped = raw.replace(/\D/g, "");
  if (stripped.length < 8) return false;
  let total = 0;
  for (let idx = stripped.length - 1, alt = false; idx >= 0; idx--, alt = !alt) {
    let digit = parseInt(stripped[idx], 10);
    if (alt) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    total += digit;
  }
  return total % 10 === 0;
}

// ── US SSN area-number check ───────────────────────────────────────────────

export function checkSsnArea(raw: string): boolean {
  const digits = raw.replace(/\D/g, "");
  if (digits.length !== 9) return false;
  const area = digits.slice(0, 3);
  const group = digits.slice(3, 5);
  const serial = digits.slice(5);
  if (area === "000" || area === "666" || parseInt(area, 10) >= 900) return false;
  if (group === "00" || serial === "0000") return false;
  return true;
}

// ── IBAN structural check ──────────────────────────────────────────────────

const IBAN_COUNTRY_LENGTHS: Record<string, number> = {
  AL: 28, AD: 24, AT: 20, AZ: 28, BH: 22, BY: 28,
  BE: 16, BA: 20, BR: 29, BG: 22, CR: 22, HR: 21,
  CY: 28, CZ: 24, DK: 18, DO: 28, TL: 23, EE: 20,
  FO: 18, FI: 18, FR: 27, GE: 22, DE: 22, GI: 23,
  GR: 27, GL: 18, GT: 28, HU: 28, IS: 26, IQ: 23,
  IE: 22, IL: 23, IT: 27, JO: 30, KZ: 20, XK: 20,
  KW: 30, LV: 21, LB: 28, LI: 21, LT: 20, LU: 20,
  MK: 19, MT: 31, MR: 27, MU: 30, MC: 27, MD: 24,
  ME: 22, NL: 18, NO: 15, PK: 24, PS: 29, PL: 28,
  PT: 25, QA: 29, RO: 24, SM: 27, SA: 24, RS: 22,
  SC: 31, SK: 24, SI: 19, ES: 24, SE: 24, CH: 21,
  TN: 24, TR: 26, AE: 23, GB: 22, VA: 22, VG: 24,
};

export function checkIbanStructure(raw: string): boolean {
  const cleaned = raw.replace(/ /g, "").toUpperCase();
  if (cleaned.length < 15 || cleaned.length > 34) return false;
  const country = cleaned.slice(0, 2);
  if (!/^[A-Z]{2}$/.test(country)) return false;
  const expectedLen = IBAN_COUNTRY_LENGTHS[country];
  if (expectedLen && cleaned.length !== expectedLen) return false;

  // ISO 7064 Mod-97 verification
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
  let numericRepr = "";
  for (const ch of rearranged) {
    if (/\d/.test(ch)) {
      numericRepr += ch;
    } else if (/[A-Z]/.test(ch)) {
      numericRepr += (ch.charCodeAt(0) - 55).toString();
    } else {
      return false;
    }
  }

  // BigInt is needed for numbers exceeding Number.MAX_SAFE_INTEGER
  return BigInt(numericRepr) % 97n === 1n;
}

// ── US ABA Routing Number ──────────────────────────────────────────────────

export function checkAbaRouting(raw: string): boolean {
  const digits = raw.replace(/\D/g, "");
  if (digits.length !== 9) return false;
  const d = digits.split("").map(Number);
  const weighted = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]);
  return weighted % 10 === 0;
}

// ── VIN (Vehicle Identification Number) ────────────────────────────────────

const VIN_TRANSLITERATION: Record<string, number> = {
  A: 1, B: 2, C: 3, D: 4, E: 5, F: 6, G: 7, H: 8,
  J: 1, K: 2, L: 3, M: 4, N: 5, P: 7, R: 9,
  S: 2, T: 3, U: 4, V: 5, W: 6, X: 7, Y: 8, Z: 9,
};
const VIN_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];

export function checkVinFormat(raw: string): boolean {
  const vin = raw.trim().toUpperCase();
  if (vin.length !== 17) return false;
  if (/[IOQ]/.test(vin)) return false;

  let total = 0;
  for (let i = 0; i < 17; i++) {
    const ch = vin[i];
    let val: number;
    if (/\d/.test(ch)) {
      val = parseInt(ch, 10);
    } else {
      const mapped = VIN_TRANSLITERATION[ch];
      if (mapped === undefined) return false;
      val = mapped;
    }
    total += val * VIN_WEIGHTS[i];
  }
  const remainder = total % 11;
  const expected = remainder === 10 ? "X" : remainder.toString();
  return vin[8] === expected;
}

// ── Bitcoin address basic format ───────────────────────────────────────────

export function checkBtcFormat(raw: string): boolean {
  const addr = raw.trim();
  if (addr.length < 26 || addr.length > 62) return false;
  if (!(addr[0] === "1" || addr[0] === "3" || addr.startsWith("bc1"))) return false;
  return true;
}

// ── IPv4 octet-range check ─────────────────────────────────────────────────

export function checkIpv4Octets(raw: string): boolean {
  const parts = raw.trim().split(".");
  if (parts.length !== 4) return false;
  for (const segment of parts) {
    if (!/^\d+$/.test(segment)) return false;
    const n = parseInt(segment, 10);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

// ── Canadian SIN (Luhn-9) ──────────────────────────────────────────────────

export function checkCaSin(raw: string): boolean {
  const digits = raw.replace(/\D/g, "");
  if (digits.length !== 9) return false;
  
  let total = 0;
  for (let idx = 0; idx < digits.length; idx++) {
    let val = parseInt(digits[idx], 10);
    if (idx % 2 === 1) { // 1st is 0, 2nd is 1...
      val *= 2;
      if (val > 9) val -= 9;
    }
    total += val;
  }
  return total % 10 === 0;
}

// ── UK National Insurance Number (NINO) ────────────────────────────────────

const UK_NINO_REGEX = /^(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D]$/;

export function checkUkNino(raw: string): boolean {
  const cleaned = raw.replace(/ /g, "").toUpperCase();
  if (cleaned.length !== 9) return false;
  return UK_NINO_REGEX.test(cleaned);
}

// ── Spanish DNI/NIE (8 digits + 1 letter) ───────────────────────────────────

export function checkEsId(raw: string): boolean {
  const cleaned = raw.replace(/[\s-]/g, "").toUpperCase();
  if (cleaned.length !== 9) return false;

  const mapping: Record<string, string> = { X: "0", Y: "1", Z: "2" };
  const firstChar = cleaned[0];
  let numStr: string;

  if (firstChar in mapping) {
    numStr = mapping[firstChar] + cleaned.slice(1, 8);
  } else if (/^\d$/.test(firstChar)) {
    numStr = cleaned.slice(0, 8);
  } else {
    return false;
  }

  if (!/^\d+$/.test(numStr)) return false;
  const num = parseInt(numStr, 10);
  const validLetters = "TRWAGMYFPDXBNJZSQVHLCKE";
  return cleaned[8] === validLetters[num % 23];
}

// ── Dispatcher ─────────────────────────────────────────────────────────────

type ValidatorFn = (raw: string) => boolean;

const VALIDATOR_DISPATCH: Record<string, ValidatorFn> = {
  luhn: checkLuhn,
  ssn_area: checkSsnArea,
  iban: checkIbanStructure,
  aba_check: checkAbaRouting,
  vin_format: checkVinFormat,
  btc_format: checkBtcFormat,
  ipv4: checkIpv4Octets,
  ca_sin: checkCaSin,
  uk_nino: checkUkNino,
  es_id: checkEsId,
};

/**
 * Run the appropriate hard-validator for a given validator tag.
 *
 * @example
 * ```ts
 * const engine = new DLPValidationEngine();
 * const passed = engine.run("luhn", "4111111111111111");
 * ```
 */
export class DLPValidationEngine {
  /**
   * Execute the validator identified by tag.
   *
   * @returns `true` — value passed checksum → confidence override.
   * @returns `false` — value failed → confidence penalty.
   * @returns `null` — no validator registered for tag.
   */
  run(tag: string | null | undefined, rawValue: string): boolean | null {
    if (!tag) return null;
    const fn = VALIDATOR_DISPATCH[tag];
    if (!fn) return null;
    try {
      return fn(rawValue);
    } catch {
      return false;
    }
  }

  /** Return all registered validator tag names. */
  static availableTags(): string[] {
    return Object.keys(VALIDATOR_DISPATCH);
  }
}
