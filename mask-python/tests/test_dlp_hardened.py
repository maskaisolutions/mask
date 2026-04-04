import pytest
from mask_privacy import get_scanner

def mask_sync(text):
    return get_scanner().scan_and_tokenize(text, pipeline=['dlp'])



def test_locale_aware_precision():
    # Spanish DNI in English context
    raw = "My DNI is 12345678Z"
    masked = mask_sync(raw)
    assert "000" in masked # Spanish ID token prefix

if __name__ == "__main__":
    test_locale_aware_precision()
    print("All Python hardening tests passed!")
