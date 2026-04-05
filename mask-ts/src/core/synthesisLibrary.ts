/**
 * Synthesis Library — Identical components to the Python SDK.
 */

export const FIRST_NAMES: string[] = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica"
];
while (FIRST_NAMES.length < 2048) { FIRST_NAMES.push(`NameEx_${FIRST_NAMES.length}`); }

export const CONNECTORS: string[] = [
    "of", "from", "van", "del", "di", "von", "le", "la", "de", "el",
    "the", "near", "at", "by", "under", "over", "across", "beyond", "within", "without",
    "and", "with", "aka", "alias", "formally", "lately", "born", "styled", "known", "called",
    "st", "al", "bin", "ibn", "abu", "ben", "bar", "fitz", "mac", "mc",
    "o", "da", "dos", "das", "do", "du", "della", "degli", "dei", "delle",
    "sur", "ter", "ten", "zu", "zum", "zur", "auf", "an", "der", "die", "das",
    "pro", "anti", "ex", "quasi"
];

export const SURNAME_ROOTS: string[] = [
    "Silver", "Gold", "Iron", "Stone", "Rock", "Wood", "Leaf", "Rain", "Snow", "Wind",
    "Storm", "Cloud", "Sun", "Moon", "Star", "Sky", "Sea", "Lake", "River", "Brook",
    "Hill", "Mount", "Vale", "Glen", "Dale", "Field", "Meadow", "Forest", "Grove", "Wild"
];
while (SURNAME_ROOTS.length < 4096) { SURNAME_ROOTS.push(`RootEx_${SURNAME_ROOTS.length}`); }

export const SURNAME_SUFFIXES: string[] = [
    "son", "man", "field", "wood", "berg", "stein", "ov", "ova", "ski", "ska",
    "ez", "ez", "ia", "ic", "os", "as", "is", "us", "er", "en",
    "ard", "ier", "eau", "oux", "ly", "ley", "ton", "don", "ham", "ford",
    "wick", "shire", "land", "way", "side", "gate", "bridge", "well", "pool", "cliff",
    "bank", "shore", "hart", "foot", "head", "more", "less", "ness", "ship", "ward"
];
while (SURNAME_SUFFIXES.length < 512) { SURNAME_SUFFIXES.push(`SuffixEx_${SURNAME_SUFFIXES.length}`); }

export const SYLLABLES: string[] = [
    "San", "Ver", "Dina", "Lon", "Don", "Chi", "Ca", "Go", "New", "York",
    "Los", "An", "Ge", "Les", "Pa", "Ris", "Ber", "Lin", "Mad", "Rid"
];
while (SYLLABLES.length < 1000) { SYLLABLES.push(`Syl_${SYLLABLES.length}`); }
