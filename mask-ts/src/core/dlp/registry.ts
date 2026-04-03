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
  isHighEntropy: boolean;
  supportedLocales: string[];
}

// ── Locale-specific auxiliary patterns ──────────────────────────────────────

export const LOCALE_NAME_RULES: Record<string, RegExp[]> = {
  en: [
    /\b[A-Z][a-z\-\']+ [A-Z][a-z\-\']+(?:\s+[A-Z][a-z\-\']+)?\b/g,
    /\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z\-\']+\b/g,
  ],
  es: [
    /\b[A-Z][a-záéíóúñ\-\']+ [A-Z][a-záéíóúñ\-\']+(?:\s+[A-Z][a-záéíóúñ\-\']+)?\b/g,
    /\b(?:Sr|Sra|Srta)\.?\s+[A-Z][a-záéíóúñ\-\']+\b/g,
  ],
  fr: [
    /\b[A-Z][a-zàâçéèêëïîôùûü\-\']+ [A-Z][a-zàâçéèêëïîôùûü\-\']+\b/g,
    /\b(?:M|Mme|Mlle)\.?\s+[A-Z][a-zàâçéèêëïîôùûü\-\+\']+\b/g,
  ],
  de: [
    /\b[A-Z][a-zäöüß\-\']+ [A-Z][a-zäöüß\-\']+\b/g,
    /\b(?:Herr|Frau)\.?\s+[A-Z][a-zäöüß\-\']+\b/g,
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
  regexSource: string | RegExp,
  terms: string[],
  risk: number,
  category: SensitiveCategory,
  validatorTag: string | null,
  isHighEntropy?: boolean,
  supportedLocales?: string[],
];

const RAW_PATTERNS: RawEntry[] = [
  // ── FINANCIAL ──────────────────────────────────────────────────────
  ["US_SSN", "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b",
    ["ssn", "social security", "tax id", "taxpayer"], 0.95, SensitiveCategory.FINANCIAL, "ssn_area"],

  ["CREDIT_CARD_NUMBER", "\\b(?:4\\d{3}|5[1-5]\\d{2}|3[47]\\d{2}|6(?:011|5\\d{2}))[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b",
    ["card", "credit", "visa", "mastercard", "amex", "payment"], 0.97, SensitiveCategory.FINANCIAL, "luhn"],

  ["INTL_BANK_IBAN", "\\b[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}[A-Z0-9]{0,16}\\b",
    ["iban", "swift", "sepa", "wire", "bank transfer"], 0.96, SensitiveCategory.FINANCIAL, "iban"],

  ["CRYPTO_BTC", "\\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\\b",
    ["bitcoin", "btc", "wallet", "crypto"], 0.94, SensitiveCategory.FINANCIAL, "btc_format"],

  ["CRYPTO_ETH", "\\b0x[a-fA-F0-9]{40}\\b",
    ["ethereum", "eth", "wallet", "0x"], 0.93, SensitiveCategory.FINANCIAL, null],

  ["US_ABA_ROUTING", /(?<!\d)\d{9}(?!\d)/,
    ["routing", "aba", "wire", "bank"], 0.88, SensitiveCategory.FINANCIAL, "aba_check"],

  ["BANK_ACCT_NUM", /(?<!\d)\d{8,17}(?!\d)/,
    ["account", "checking", "savings", "deposit", "bank"], 0.50, SensitiveCategory.FINANCIAL, "luhn_soft"],

  ["SWIFT_BIC", "\\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\\b",
    ["swift", "bic", "bank code", "transfer"], 0.60, SensitiveCategory.FINANCIAL, null],

  // ── CONTACT ────────────────────────────────────────────────────────
  ["EMAIL_ADDR", "\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}\\b",
    ["email", "mail", "contact", "address"], 0.99, SensitiveCategory.CONTACT, null],

  ["PHONE_NUM", /(?<!\d)(?:\+?[1-9]\d{0,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}(?!\d)/,
    ["phone", "call", "mobile", "tel", "whatsapp", "number"], 0.80, SensitiveCategory.CONTACT, null],

  ["PHONE_NUM_INTL", /(?<!\d)\+(?:[1-9]\d{0,3})[-.\s]?\(?\d{1,5}\)?(?:[-.\s]?\d{2,4}){2,4}(?!\d)/,
    ["phone", "call", "mobile", "tel"], 0.80, SensitiveCategory.CONTACT, null],

  ["IPV4_ADDR", "\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b",
    ["ip", "server", "host", "network", "address"], 0.94, SensitiveCategory.CONTACT, "ipv4"],

  ["IPV6_ADDR", "\\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\\b",
    ["ipv6", "ip", "network", "server"], 0.93, SensitiveCategory.CONTACT, null],

  ["HW_MAC_ADDR", "\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b",
    ["mac", "hardware", "network", "device"], 0.91, SensitiveCategory.CONTACT, null],

  // ── PERSONAL ───────────────────────────────────────────────────────
  ["BIRTH_DATE", "\\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\\d|3[01])[/-](?:19|20)\\d{2}\\b",
    ["birth", "dob", "born", "birthday", "date of birth"], 0.88, SensitiveCategory.PERSONAL, null],

  ["US_DRIVERS_LIC", "\\b(?:[A-Z]\\d{7,12}|\\d{7,12}[A-Z]?)\\b",
    ["driver", "license", "licence", "dl", "dmv"], 0.55, SensitiveCategory.PERSONAL, null],

  ["US_PASSPORT_NUM", "\\b[A-Z]\\d{8}\\b",
    ["passport", "travel", "visa", "immigration"], 0.87, SensitiveCategory.PERSONAL, null],

  // ── VEHICLE ────────────────────────────────────────────────────────
  ["VEHICLE_VIN", "\\b[A-HJ-NPR-Z0-9]{17}\\b",
    ["vin", "vehicle", "chassis", "automobile"], 0.92, SensitiveCategory.VEHICLE, "vin_format"],

  ["VEHICLE_PLATE", "\\b[A-Z0-9]{1,3}[\\-\\s][A-Z0-9]{1,4}[\\-\\s][A-Z0-9]{1,4}\\b",
    ["plate", "registration", "vehicle", "plaka"], 0.45, SensitiveCategory.VEHICLE, null],

  // ── HEALTHCARE ─────────────────────────────────────────────────────
  ["MED_RECORD_ID", "\\b(?:MRN|Patient ID|Medical Record)[:\\s]*[A-Z0-9]{6,10}\\b",
    ["patient", "medical", "record", "mrn", "hospital"], 0.96, SensitiveCategory.HEALTHCARE, null],

  ["US_MEDICARE_ID", "\\b\\d{3}-\\d{2}-\\d{4}[A-Z]\\b",
    ["medicare", "cms", "beneficiary", "health insurance"], 0.91, SensitiveCategory.HEALTHCARE, null],

  ["US_DEA_NUM", "\\b[A-Z]{2}\\d{7}\\b",
    ["dea", "prescriber", "drug", "enforcement"], 0.89, SensitiveCategory.HEALTHCARE, null],

  ["US_NPI_NUM", "\\b\\d{10}\\b",
    ["npi", "provider", "national provider", "healthcare"], 0.87, SensitiveCategory.HEALTHCARE, null],

  // ── IDENTITY_US ────────────────────────────────────────────────────
  ["US_EIN_TAX", "\\b\\d{2}-\\d{7}\\b",
    ["ein", "federal", "employer", "tax id"], 0.89, SensitiveCategory.IDENTITY_US, null],

  // ── IDENTITY_INTL ──────────────────────────────────────────────────
  ["UK_NATL_INS", "\\b[A-Z]{2}\\d{6}[A-Z]\\b",
    ["nino", "national insurance", "ni number", "uk"], 0.90, SensitiveCategory.IDENTITY_INTL, "uk_nino"],

  ["CA_SOCIAL_INS", "\\b\\d{3}[-\\s]?\\d{3}[-\\s]?\\d{3}\\b",
    ["sin", "social insurance", "canada", "canadian"], 0.89, SensitiveCategory.IDENTITY_INTL, "ca_sin"],

  ["FR_INSEE_NUM", "\\b[12]\\d{2}[01]\\d\\d{8}\\d{2}\\b",
    ["insee", "sécurité sociale", "france", "numéro"], 0.88, SensitiveCategory.IDENTITY_INTL, "fr_insee"],

  ["DE_STEUER_ID", "\\b\\d{2}\\s?\\d{3}\\s?\\d{3}\\s?\\d{3}\\b",
    ["steuer", "steuernummer", "finanzamt", "deutschland"], 0.87, SensitiveCategory.IDENTITY_INTL, null],

  ["TR_TCID", "\\b[1-9]\\d{9}[02468]\\b",
    ["tc", "kimlik", "vatandaşlık", "nüfus", "türkiye"], 0.92, SensitiveCategory.IDENTITY_INTL, "tcid"],

  ["SA_NATIONAL_ID", "\\b1\\d{9}\\b",
    ["هوية", "رقم الهوية", "saudi", "وطنية", "identity"], 0.91, SensitiveCategory.IDENTITY_INTL, "saudi_nid"],

  ["UAE_EMIRATES_ID", "784-\\d{4}-\\d{7}-\\d",
    ["emirates", "هوية", "uae", "emirati", "identity"], 0.93, SensitiveCategory.IDENTITY_INTL, "luhn", true, ["*", "ar"]],

  ["CN_ID", "[1-9]\\d{5}(?:18|19|20)\\d{2}(?:0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])\\d{3}[0-9Xx]",
    ["身份证", "身份号码", "id card", "china"], 0.95, SensitiveCategory.IDENTITY_INTL, "cn_id", true, ["*", "zh"]],

  ["JA_MY_NUMBER", "\\d{12}",
    ["マイナンバー", "個人番号", "my number", "japan"], 0.94, SensitiveCategory.IDENTITY_INTL, "ja_id", true, ["*", "ja"]],

  ["ES_DNI", "(?:\\d{8}[A-Z]|[XYZ]\\d{7}[A-Z])",
    ["dni", "nie", "identidad", "nif", "spain"], 0.94, SensitiveCategory.IDENTITY_INTL, "es_id", true, ["*", "es"]],

  ["INTL_PASSPORT", "[A-Z0-9]{6,12}",
    ["passport", "travel", "immigration", "visa"], 0.60, SensitiveCategory.IDENTITY_INTL, null, true, ["*"]],

  // ── CORPORATE ──────────────────────────────────────────────────────
  ["CORP_EMPLOYEE_ID", "(?:EMP|EMPLOYEE|ID)[:\\s]?[A-Z0-9]{5,10}",
    ["employee", "staff", "personnel", "worker"], 0.55, SensitiveCategory.CORPORATE, null],
];

// ── Master pattern catalogue ─────────────────────────────────────────────

/**
 * Immutable catalogue of sensitive-data regex signatures.
 */
export class DLPPatternRegistry {
  private readonly catalogue: Map<string, PatternDescriptor> = new Map();
  private readonly localeCategoryRegexMap: Map<string, Map<string, { re: RegExp; typeOrder: string[] }>> = new Map();

  constructor(loadGroups?: ReadonlySet<SensitiveCategory>) {
    this.buildCatalogue(loadGroups ?? null);
    for (const loc of ["*", "en", "es", "fr", "de", "tr", "ar", "ja", "zh"]) {
      this.compileForLocale(loc);
    }
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

  namePatternsFor(lang: LanguageTag | string): RegExp[] {
    return LOCALE_NAME_RULES[lang] ?? LOCALE_NAME_RULES["en"];
  }

  addressPatternsFor(lang: LanguageTag | string): RegExp[] {
    return LOCALE_ADDRESS_RULES[lang] ?? LOCALE_ADDRESS_RULES["en"];
  }

  getCategoryRegexesMap(locale: string = "en"): Map<string, { re: RegExp; typeOrder: string[] }> {
    if (!this.localeCategoryRegexMap.has(locale)) {
      this.compileForLocale(locale);
    }
    return this.localeCategoryRegexMap.get(locale)!;
  }

  getCategoryTypeMap(categoryName: string, locale: string = "en"): string[] {
    return this.localeCategoryRegexMap.get(locale)?.get(categoryName)?.typeOrder ?? [];
  }

  private compileForLocale(locale: string): void {
    const localePool = new Map<string, [string, PatternDescriptor][]>();

    for (const [typeName, desc] of this.catalogue.entries()) {
      if (desc.supportedLocales.includes("*") || desc.supportedLocales.includes(locale)) {
        const catKey = desc.category;
        if (!localePool.has(catKey)) localePool.set(catKey, []);
        localePool.get(catKey)!.push([typeName, desc]);
      }
    }

    const categoryMap = new Map<string, { re: RegExp; typeOrder: string[] }>();

    for (const [catKey, entries] of localePool.entries()) {
      entries.sort(([, a], [, b]) => {
        const aVal = a.validatorTag ? 0 : 1;
        const bVal = b.validatorTag ? 0 : 1;
        if (aVal !== bVal) return aVal - bVal;
        return b.compiledRe.source.length - a.compiledRe.source.length;
      });

      const parts: string[] = [];
      const typeOrder: string[] = [];
      for (const [typeName, desc] of entries) {
        parts.push(`(?<${typeName}>${desc.compiledRe.source})`);
        typeOrder.push(typeName);
      }

      const combinedSource = parts.join('|');
      const needsI = entries.some(([, d]) => d.compiledRe.flags.includes('i'));
      const flags = needsI ? 'gi' : 'g';

      try {
        const re = new RegExp(combinedSource, flags);
        categoryMap.set(catKey, { re, typeOrder });
      } catch (err) {
        console.error(`[DLPPatternRegistry] Locale [${locale}] category [${catKey}] failed:`, err);
      }
    }

    this.localeCategoryRegexMap.set(locale, categoryMap);
  }

  private buildCatalogue(restrict: ReadonlySet<SensitiveCategory> | null): void {
    for (const entry of RAW_PATTERNS) {
      const [typeName, regexSource, terms, risk, cat, vtag, isHighEntropy, supportedLocales] = entry;
      if (restrict !== null && !restrict.has(cat)) continue;

      let re: RegExp;
      if (regexSource instanceof RegExp) {
        re = regexSource;
      } else {
        re = new RegExp(regexSource, "g");
      }

      this.catalogue.set(typeName, {
        compiledRe: re,
        proximityTerms: new Set(terms),
        baseRisk: risk,
        category: cat,
        validatorTag: vtag,
        isHighEntropy: isHighEntropy ?? (vtag !== null),
        supportedLocales: supportedLocales ?? ["*"],
      });
    }
  }
}
