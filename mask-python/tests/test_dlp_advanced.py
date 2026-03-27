import pytest
import re
from mask_privacy.core.dlp.assessor import LanguageContextResolver
from mask_privacy.core.dlp.registry import DLPPatternRegistry, SensitiveCategory
from mask_privacy.core.dlp.handlers import DLPValidationEngine
from mask_privacy.core.dlp.scorer import DLPConfidenceScorer
from mask_privacy.core.fpe import generate_fpe_token, looks_like_token
from mask_privacy.core.scanner import get_scanner

def test_language_resolver():
    resolver = LanguageContextResolver()
    assert resolver.resolve("TC Kimlik Numarası") == "tr"  # ı is Turkish
    assert resolver.resolve("رقم الهوية الوطنية") == "ar"  # Arabic script
    assert resolver.resolve("Herr Schmidt, Steuer-Id für München") == "de"  # de
    assert resolver.resolve("Hello world, my SSN is 111") == "en"

def test_dlp_registry_and_validators():
    reg = DLPPatternRegistry()
    assert "TR_TCID" in reg.type_names
    assert "SA_NATIONAL_ID" in reg.type_names
    
    eng = DLPValidationEngine()
    # TCID checksum
    assert eng.run("tcid", "10000000146") is True  # Valid TR TCID
    assert eng.run("tcid", "10000000147") is False # Invalid
    
    # Saudi NID checksum
    assert eng.run("saudi_nid", "1000000008") is True # Mathematically valid checksum
    assert eng.run("saudi_nid", "1234567890") is False

def test_dlp_confidence_scorer():
    scorer = DLPConfidenceScorer()
    
    # Hard-validator override
    score = scorer.score(
        base_risk=0.5, match_start=0, match_end=10, 
        full_text="1234567890", proximity_terms=frozenset(), validator_passed=True
    )
    assert score == 0.99
    
    # Keyword boost
    score2 = scorer.score(
        base_risk=0.8, match_start=15, match_end=26,
        full_text="My tc kimlik is 10000000146 here", 
        proximity_terms=frozenset({"tc", "kimlik"}), validator_passed=None
    )
    assert score2 > 0.8  # Boost applied

def test_fpe_generation_for_new_dlp_types():
    tcid = "10000000146"
    tcid_token = generate_fpe_token(tcid)
    assert len(tcid_token) == 11
    assert tcid_token.startswith("990000")
    assert int(tcid_token[-1]) % 2 == 0
    assert looks_like_token(tcid_token)

    saudi = "1234567890"
    saudi_tok = generate_fpe_token(saudi)
    assert len(saudi_tok) == 10
    assert saudi_tok.startswith("100000")
    assert looks_like_token(saudi_tok)
    
    uae = "784-1234-1234567-1"
    uae_tok = generate_fpe_token(uae)
    assert uae_tok.startswith("784-0000-")
    assert len(uae_tok) == 18
    assert looks_like_token(uae_tok)

def test_scanner_integration_dlp():
    scanner = get_scanner()
    # Provide enough Turkish characters for the assessor to select 'tr' locale
    text = "User from Istanbul has TC Kimlik Numarası 10000000146 and phone +905551234567."
    res, entities = scanner._tier0_dlp_heuristic(text, generate_fpe_token, 0.7)
    
    assert len(entities) > 0
    types = [e["type"] for e in entities]
    assert "TR_TCID" in types
    
    # Just verify that token was generated correctly in Tier 0 output
    tcid_entity = next(e for e in entities if e["type"] == "TR_TCID")
    assert "Numarası" not in tcid_entity["masked_value"]
    assert looks_like_token(tcid_entity["masked_value"])
