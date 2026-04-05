import pytest
import hmac
import hashlib
from mask_privacy.core.fpe import FF1, _get_bijective_tweak, _get_master_key, generate_fpe_token
from mask_privacy import config

@pytest.fixture(autouse=True)
def setup_bijective_config(monkeypatch):
    monkeypatch.setenv("MASK_BIJECTIVE_MODE", "true")
    monkeypatch.setenv("MASK_MASTER_KEY", "fixed-test-key-for-bijective-proof")
    monkeypatch.setenv("MASK_TENANT_ID", "tenant-a")
    # Reset master key cache
    from mask_privacy.core.fpe import reset_master_key
    reset_master_key()

def test_cross_sdk_parity_golden_vector():
    """Verify bit-for-bit parity with TypeScript. Input: 0, Key: fixed-..., Tenant: tenant-a."""
    key = b"fixed-test-key-for-bijective-proof"[:16]
    # Derive tweak exactly as in production
    base = b"tenant-a"
    tweak = hmac.new(b"fixed-test-key-for-bijective-proof", base, hashlib.sha256).digest()
    engine = FF1(key, tweak)
    cipher = engine.encrypt(0)
    # This value was confirmed against the synchronized test key/tenant
    assert str(cipher) == "14723038793896035711"

def test_ff1_bijective_property():
    """Verify that FF1 is a true bijection (decrypt(encrypt(x)) == x)."""
    key = _get_master_key()[:16]
    tweak = _get_bijective_tweak()
    engine = FF1(key, tweak)
    
    # Test across broad 64-bit domain
    test_values = [
        0, 1, 100, 2**31 - 1, 2**32, 2**32 + 1,
        2**63 - 1, 2**64 - 1,
        1234567890123456789
    ]
    
    for val in test_values:
        cipher = engine.encrypt(val)
        decrypted = engine.decrypt(cipher)
        assert val == decrypted, f"FF1 bijection failed for value {val}"

def test_tenant_isolation():
    """Verify that tokens are unique per tenant (referential integrity check)."""
    name = "John Doe"
    
    # Tenant A
    config.MASK_TENANT_ID = "tenant-a"
    token_a = generate_fpe_token(name, "PERSON")
    
    # Tenant B
    config.MASK_TENANT_ID = "tenant-b"
    token_b = generate_fpe_token(name, "PERSON")
    
    assert token_a != token_b, "Tenant isolation failed: different tenants produced same token"
    
    # Back to A (Determinism)
    config.MASK_TENANT_ID = "tenant-a"
    token_a_verify = generate_fpe_token(name, "PERSON")
    assert token_a == token_a_verify, "Determinism failed: same tenant produced different tokens"

def test_synthesis_human_readability():
    """Verify that Bijective tokens are human-readable synthesis strings."""
    res = generate_fpe_token("Jane Doe", "PERSON")
    # Bijective tokens should be roughly "Name Surname-Tag"
    assert "-" in res, f"Token {res} does not match expected Bijective pattern"
    assert len(res.split("-")[-1]) == 4, "Bijective token numeric tag should be 4 digits"

def test_location_synthesis():
    """Verify bijective location synthesis."""
    res = generate_fpe_token("San Francisco", "LOCATION")
    # Bijective location pattern: CityName-Tag (3 digits)
    assert "-" in res
    tag = res.split("-")[-1]
    assert len(tag) >= 3, f"Location tag {tag} should be at least 3 digits"
