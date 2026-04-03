import pytest
from mask_privacy import get_scanner

def mask_sync(text):
    return get_scanner().scan_and_tokenize(text, pipeline=['dlp'])

def test_chinese_id_fragmentation_fix():
    # Valid 18-digit Chinese ID (with correct checksum '7')
    raw = "My ID is 110101199003074477"
    masked = mask_sync(raw)
    
    # Should mask to a single CN_ID token with prefix 88000019900101
    assert "88000019900101" in masked

def test_fuzzy_fail_safe():
    # ID with a typo (checksum fails)
    raw = "ID with typo: 110101199003074475"
    masked = mask_sync(raw)
    
    # Should still be masked (leaked if Priority 0 wasn't fuzzy)
    # High-entropy IDs should beat generic phone numbers even when fuzzy
    assert "110101199003074475" not in masked
    assert "88000019900101" in masked

def test_locale_aware_precision():
    # Spanish DNI in English context
    raw = "My DNI is 12345678Z"
    masked = mask_sync(raw)
    assert "000" in masked # Spanish ID token prefix

if __name__ == "__main__":
    test_chinese_id_fragmentation_fix()
    test_fuzzy_fail_safe()
    test_locale_aware_precision()
    print("All Python hardening tests passed!")
