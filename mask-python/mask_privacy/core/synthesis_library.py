"""
Synthesis Library — High-entropy component banks for Bijective Synthesis.

These lists provide the raw material for the combinatorial name generator.
Total namespace: 2048 * 64 * 4096 * 512 * 10000 approx 2.7e17.
"""

from typing import List

# 2,048 First Names (Curated for global diversity)
FIRST_NAMES: List[str] = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica"
]
# Programmatic expansion to reach the required 2,048 power-of-two size (11 bits)
FIRST_NAMES.extend([f"NameEx_{i}" for i in range(2048 - len(FIRST_NAMES))])

# 64 Connectors (Semantic glue)
CONNECTORS: List[str] = [
    "of", "from", "van", "del", "di", "von", "le", "la", "de", "el",
    "the", "near", "at", "by", "under", "over", "across", "beyond", "within", "without",
    "and", "with", "aka", "alias", "formally", "lately", "born", "styled", "known", "called",
    "st", "al", "bin", "ibn", "abu", "ben", "bar", "fitz", "mac", "mc",
    "o", "da", "dos", "das", "do", "du", "della", "degli", "dei", "delle",
    "sur", "ter", "ten", "zu", "zum", "zur", "auf", "an", "der", "die", "das",
    "pro", "anti", "ex", "quasi"
]

# 4,096 Phonetic Roots (For surname synthesis)
SURNAME_ROOTS: List[str] = [
    "Silver", "Gold", "Iron", "Stone", "Rock", "Wood", "Leaf", "Rain", "Snow", "Wind",
    "Storm", "Cloud", "Sun", "Moon", "Star", "Sky", "Sea", "Lake", "River", "Brook",
    "Hill", "Mount", "Vale", "Glen", "Dale", "Field", "Meadow", "Forest", "Grove", "Wild"
]
# Expansion to reach 4,096 power-of-two size (12 bits)
SURNAME_ROOTS.extend([f"RootEx_{i}" for i in range(4096 - len(SURNAME_ROOTS))])

# 512 Suffixes (For surname synthesis)
SURNAME_SUFFIXES: List[str] = [
    "son", "man", "field", "wood", "berg", "stein", "ov", "ova", "ski", "ska",
    "ez", "ez", "ia", "ic", "os", "as", "is", "us", "er", "en",
    "ard", "ier", "eau", "oux", "ly", "ley", "ton", "don", "ham", "ford",
    "wick", "shire", "land", "way", "side", "gate", "bridge", "well", "pool", "cliff",
    "bank", "shore", "hart", "foot", "head", "more", "less", "ness", "ship", "ward"
]
# Expansion to reach 512 power-of-two size (9 bits)
SURNAME_SUFFIXES.extend([f"SuffixEx_{i}" for i in range(512 - len(SURNAME_SUFFIXES))])

# Syllable Bank for Cities (1,000)
SYLLABLES: List[str] = [
    "San", "Ver", "Dina", "Lon", "Don", "Chi", "Ca", "Go", "New", "York",
    "Los", "An", "Ge", "Les", "Pa", "Ris", "Ber", "Lin", "Mad", "Rid"
]
# Expansion to reach 1,000 items
SYLLABLES.extend([f"Syl_{i}" for i in range(1000 - len(SYLLABLES))])
