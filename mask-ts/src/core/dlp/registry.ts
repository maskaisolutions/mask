/**
 * DLP Pattern Registry — Centralised catalogue of 50+ sensitive-data signatures.
 *
 * Each entry bundles a compiled regex, a list of proximity keywords (used by
 * the scorer for context boosting), a base leakage-risk probability, and an
 * optional hard-validator tag that tells the DLPValidationEngine which
 * checksum to run after the initial pattern match.
 *
 * Patterns are organised into SensitiveCategory groups so that callers can
 * selectively load only the groups relevant to their compliance scope.
 */

import type { LanguageTag } from "./assessor";

// ── Category taxonomy ──────────────────────────────────────────────────────

export enum SensitiveCategory {
  FINANCIAL = "FINANCIAL",
  CONTACT = "CONTACT",
  PERSONAL = "PERSONAL",
  HEALTHCARE = "HEALTHCARE",
  IDENTITY_US = "IDENTITY_US",
  IDENTITY_INTL = "IDENTITY_INTL",
  VEHICLE = "VEHICLE",
  CORPORATE = "CORPORATE",
}

// ── Single pattern descriptor ──────────────────────────────────────────────

export interface PatternDescriptor {
  compiledRe: RegExp;
  proximityTerms: ReadonlySet<string>;
  baseRisk: number;
  category: SensitiveCategory;
  validatorTag: string | null;
}

// ── Locale-specific auxiliary patterns ──────────────────────────────────────

export const LOCALE_NAME_RULES: Record<string, RegExp[]> = {
  en: [
    /\b[A-Z][a-z]+ [A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g,
    /\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+\b/g,
  ],
  es: [
    /\b[A-Z][a-záéíóúñ]+ [A-Z][a-záéíóúñ]+(?:\s+[A-Z][a-záéíóúñ]+)?\b/g,
    /\b(?:Sr|Sra|Srta)\.?\s+[A-Z][a-záéíóúñ]+\b/g,
  ],
  fr: [
    /\b[A-Z][a-zàâçéèêëïîôùûü]+ [A-Z][a-zàâçéèêëïîôùûü]+\b/g,
    /\b(?:M|Mme|Mlle)\.?\s+[A-Z][a-zàâçéèêëïîôùûü]+\b/g,
  ],
  de: [
    /\b[A-Z][a-zäöüß]+ [A-Z][a-zäöüß]+\b/g,
    /\b(?:Herr|Frau)\.?\s+[A-Z][a-zäöüß]+\b/g,
  ],
  tr: [
    /\b[A-ZÇĞİÖŞÜ][a-zçğıöşü]+ [A-ZÇĞİÖŞÜ][a-zçğıöşü]+\b/g,
    /\b(?:Bay|Bayan|Sayın)\.?\s+[A-ZÇĞİÖŞÜ][a-zçğıöşü]+\b/g,
  ],
  ar: [
    /[\u0621-\u064a][\u0600-\u06ff]+ [\u0621-\u064a][\u0600-\u06ff]+/g,
    /(?:أبو|أم|ابن|بنت)\s+[\u0621-\u064a][\u0600-\u06ff]+/gi,
  ],
  ja: [
    /\b[A-Z][a-z]+(?:moto|yama|kawa|mura|ta|da|shi|no)\s+[A-Z][a-z]+\b/g,
  ],
  zh: [
    /\b[A-Z][a-z]{1,3}\s+[A-Z][a-z]+\b/g,
  ],
};

export const LOCALE_ADDRESS_RULES: Record<string, RegExp[]> = {
  en: [
    /\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b/g,
    /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b/g,
  ],
  fr: [
    /\b\d{1,4}\s+(?:rue|avenue|boulevard|place|chemin)\s+[A-ZÀ-ÖØ-Ý][a-zà-öø-ÿ]+\b/gi,
  ],
  de: [
    /\b[A-ZÄÖÜa-zäöüß]+(?:straße|strasse|weg|gasse|platz)\s+\d{1,4}\b/g,
  ],
  tr: [
    /\b[A-ZÇĞİÖŞÜa-zçğıöşü]+\s+(?:Cad|Sok|Mah)\.?\s+/gi,
    /\b\d{5}\s+[A-ZÇĞİÖŞÜa-zçğıöşü]+\/[A-ZÇĞİÖŞÜa-zçğıöşü]+\b/g,
  ],
  ar: [
    /شارع\s+[\u0600-\u06ff]+/g,
    /حي\s+[\u0600-\u06ff]+/g,
    /(?:ص\.ب|P\.?O\.?\s*Box)\s*\d{3,6}/gi,
  ],
  uk_postcode: [
    /\b[A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2}\b/g,
  ],
  ca_postal: [
    /\b[A-Z]\d[A-Z]\s*\d[A-Z]\d\b/g,
  ],
};

// ── Raw pattern definitions ────────────────────────────────────────────────

type RawEntry = [
  typeName: string,
  regexStr: string,
  flags: string,
  terms: string[],
  risk: number,
  cat: SensitiveCategory,
  vtag: string | null,
];

const RAW_PATTERNS: RawEntry[] = [
  // ── FINANCIAL ──────────────────────────────────────────────────────
  ["US_SSN", "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b", "g",
    ["ssn", "social security", "tax id", "taxpayer"], 0.95, SensitiveCategory.FINANCIAL, "ssn_area"],

  ["CREDIT_CARD_NUMBER", "\\b(?:4\\d{3}|5[1-5]\\d{2}|3[47]\\d{2}|6(?:011|5\\d{2}))[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b", "g",
    ["card", "credit", "visa", "mastercard", "amex", "payment"], 0.97, SensitiveCategory.FINANCIAL, "luhn"],

  ["INTL_BANK_IBAN", "\\b[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}[A-Z0-9]{0,16}\\b", "g",
    ["iban", "swift", "sepa", "wire", "bank transfer"], 0.96, SensitiveCategory.FINANCIAL, "iban"],

  ["CRYPTO_BTC", "\\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\\b", "g",
    ["bitcoin", "btc", "wallet", "crypto"], 0.94, SensitiveCategory.FINANCIAL, "btc_format"],

  ["CRYPTO_ETH", "\\b0x[a-fA-F0-9]{40}\\b", "g",
    ["ethereum", "eth", "wallet", "0x"], 0.93, SensitiveCategory.FINANCIAL, null],

  ["US_ABA_ROUTING", "\\b\\d{9}\\b", "g",
    ["routing", "aba", "wire", "bank"], 0.88, SensitiveCategory.FINANCIAL, "aba_check"],

  ["BANK_ACCT_NUM", "\\b\\d{8,17}\\b", "g",
    ["account", "checking", "savings", "deposit", "bank"], 0.83, SensitiveCategory.FINANCIAL, null],

  ["SWIFT_BIC", "\\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\\b", "gi",
    ["swift", "bic", "bank code", "transfer"], 0.60, SensitiveCategory.FINANCIAL, null],

  // ── CONTACT ────────────────────────────────────────────────────────
  ["EMAIL_ADDR", "\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}\\b", "g",
    ["email", "mail", "contact", "address"], 0.99, SensitiveCategory.CONTACT, null],

  ["PHONE_NUM", "(?:\\+?[1-9]\\d{0,3}[-.\\s]?)?\\(?\\d{1,4}\\)?[-.\\s]?\\d{1,4}[-.\\s]?\\d{1,4}[-.\\s]?\\d{1,9}", "g",
    ["phone", "call", "mobile", "tel", "whatsapp", "number"], 0.92, SensitiveCategory.CONTACT, null],

  ["PHONE_NUM_INTL", "\\+(?:44|33|49|90|966|971)[-.\\s]?\\(?\\d{1,5}\\)?(?:[-.\\s]?\\d{2,4}){2,4}", "g",
    ["phone", "call", "mobile", "tel"], 0.93, SensitiveCategory.CONTACT, null],

  ["IPV4_ADDR", "\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b", "g",
    ["ip", "server", "host", "network", "address"], 0.94, SensitiveCategory.CONTACT, "ipv4"],

  ["IPV6_ADDR", "\\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\\b", "g",
    ["ipv6", "ip", "network", "server"], 0.93, SensitiveCategory.CONTACT, null],

  ["HW_MAC_ADDR", "\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b", "g",
    ["mac", "hardware", "network", "device"], 0.91, SensitiveCategory.CONTACT, null],

  // ── PERSONAL ───────────────────────────────────────────────────────
  ["BIRTH_DATE", "\\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\\d|3[01])[/-](?:19|20)\\d{2}\\b", "g",
    ["birth", "dob", "born", "birthday", "date of birth"], 0.88, SensitiveCategory.PERSONAL, null],

  ["US_DRIVERS_LIC", "\\b(?:[A-Z]\\d{7,12}|\\d{7,12}[A-Z]?)\\b", "g",
    ["driver", "license", "licence", "dl", "dmv"], 0.85, SensitiveCategory.PERSONAL, null],

  ["US_PASSPORT_NUM", "\\b[A-Z]\\d{8}\\b", "g",
    ["passport", "travel", "visa", "immigration"], 0.87, SensitiveCategory.PERSONAL, null],

  // ── VEHICLE ────────────────────────────────────────────────────────
  ["VEHICLE_VIN", "\\b[A-HJ-NPR-Z0-9]{17}\\b", "g",
    ["vin", "vehicle", "chassis", "automobile"], 0.92, SensitiveCategory.VEHICLE, "vin_format"],

  ["VEHICLE_PLATE", "\\b[A-Z0-9]{1,3}[\\-\\s][A-Z0-9]{1,4}[\\-\\s][A-Z0-9]{1,4}\\b", "g",
    ["plate", "registration", "vehicle", "plaka"], 0.45, SensitiveCategory.VEHICLE, null],

  // ── HEALTHCARE ─────────────────────────────────────────────────────
  ["MED_RECORD_ID", "\\b(?:MRN|Patient ID|Medical Record)[:\\s]*[A-Z0-9]{6,10}\\b", "g",
    ["patient", "medical", "record", "mrn", "hospital"], 0.96, SensitiveCategory.HEALTHCARE, null],

  ["US_MEDICARE_ID", "\\b\\d{3}-\\d{2}-\\d{4}[A-Z]\\b", "g",
    ["medicare", "cms", "beneficiary", "health insurance"], 0.91, SensitiveCategory.HEALTHCARE, null],

  ["US_DEA_NUM", "\\b[A-Z]{2}\\d{7}\\b", "g",
    ["dea", "prescriber", "drug", "enforcement"], 0.89, SensitiveCategory.HEALTHCARE, null],

  ["US_NPI_NUM", "\\b\\d{10}\\b", "g",
    ["npi", "provider", "national provider", "healthcare"], 0.87, SensitiveCategory.HEALTHCARE, null],

  // ── IDENTITY_US ────────────────────────────────────────────────────
  ["US_EIN_TAX", "\\b\\d{2}-\\d{7}\\b", "g",
    ["ein", "federal", "employer", "tax id"], 0.89, SensitiveCategory.IDENTITY_US, null],

  // ── IDENTITY_INTL ──────────────────────────────────────────────────
  ["UK_NATL_INS", "\\b[A-Z]{2}\\d{6}[A-Z]\\b", "g",
    ["nino", "national insurance", "ni number", "uk"], 0.90, SensitiveCategory.IDENTITY_INTL, null],

  ["CA_SOCIAL_INS", "\\b\\d{3}[-\\s]?\\d{3}[-\\s]?\\d{3}\\b", "g",
    ["sin", "social insurance", "canada", "canadian"], 0.89, SensitiveCategory.IDENTITY_INTL, null],

  ["FR_INSEE_NUM", "\\b[12]\\d{2}[01]\\d\\d{8}\\d{2}\\b", "g",
    ["insee", "sécurité sociale", "france", "numéro"], 0.88, SensitiveCategory.IDENTITY_INTL, null],

  ["DE_STEUER_ID", "\\b\\d{2}\\s?\\d{3}\\s?\\d{3}\\s?\\d{3}\\b", "g",
    ["steuer", "steuernummer", "finanzamt", "deutschland"], 0.87, SensitiveCategory.IDENTITY_INTL, null],

  ["TR_TCID", "\\b[1-9]\\d{9}[02468]\\b", "g",
    ["tc", "kimlik", "vatandaşlık", "nüfus", "türkiye"], 0.92, SensitiveCategory.IDENTITY_INTL, "tcid"],

  ["SA_NATIONAL_ID", "\\b1\\d{9}\\b", "g",
    ["هوية", "رقم الهوية", "saudi", "وطنية", "identity"], 0.91, SensitiveCategory.IDENTITY_INTL, "saudi_nid"],

  ["UAE_EMIRATES_ID", "\\b784-\\d{4}-\\d{7}-\\d\\b", "g",
    ["emirates", "هوية", "uae", "emirati", "identity"], 0.93, SensitiveCategory.IDENTITY_INTL, "luhn"],

  // ── CORPORATE ──────────────────────────────────────────────────────
  ["CORP_EMPLOYEE_ID", "\\b(?:EMP|EMPLOYEE|ID)[:\\s]?[A-Z0-9]{5,10}\\b", "gi",
    ["employee", "staff", "personnel", "worker"], 0.55, SensitiveCategory.CORPORATE, null],
];

// ── Master pattern catalogue ─────────────────────────────────────────────

/**
 * Immutable catalogue of sensitive-data regex signatures.
 *
 * @example
 * ```ts
 * const reg = new DLPPatternRegistry(); // load everything
 * const reg = new DLPPatternRegistry(new Set([SensitiveCategory.FINANCIAL]));
 * ```
 */
export class DLPPatternRegistry {
  private readonly catalogue: Map<string, PatternDescriptor> = new Map();

  constructor(loadGroups?: ReadonlySet<SensitiveCategory>) {
    this.buildCatalogue(loadGroups ?? null);
  }

  get typeNames(): string[] {
    return [...this.catalogue.keys()];
  }

  /** Yield [typeName, descriptor] pairs. */
  *iterDescriptors(): IterableIterator<[string, PatternDescriptor]> {
    yield* this.catalogue.entries();
  }

  descriptorFor(typeName: string): PatternDescriptor | undefined {
    return this.catalogue.get(typeName);
  }

  /** Return locale-tuned name regexes, falling back to English. */
  namePatternsFor(lang: LanguageTag | string): RegExp[] {
    return LOCALE_NAME_RULES[lang] ?? LOCALE_NAME_RULES["en"];
  }

  /** Return locale-tuned address regexes, falling back to English. */
  addressPatternsFor(lang: LanguageTag | string): RegExp[] {
    return LOCALE_ADDRESS_RULES[lang] ?? LOCALE_ADDRESS_RULES["en"];
  }

  private buildCatalogue(restrict: ReadonlySet<SensitiveCategory> | null): void {
    for (const [typeName, regexStr, flags, terms, risk, cat, vtag] of RAW_PATTERNS) {
      if (restrict !== null && !restrict.has(cat)) continue;
      this.catalogue.set(typeName, {
        compiledRe: new RegExp(regexStr, flags),
        proximityTerms: new Set(terms),
        baseRisk: risk,
        category: cat,
        validatorTag: vtag,
      });
    }
  }
}
