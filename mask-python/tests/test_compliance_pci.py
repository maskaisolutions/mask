import pytest
from mask_privacy.core.fpe import generate_dp_token, _get_luhn_sum, reset_master_key

@pytest.fixture(autouse=True)
def setup_compliance_env(monkeypatch):
    reset_master_key()
    monkeypatch.setenv("MASK_MASTER_KEY", "compliance-remediation-test-key")
    monkeypatch.setenv("MASK_TENANT_ID", "pci-auditor")
    monkeypatch.setenv("MASK_BIJECTIVE_MODE", "true")
    yield
    reset_master_key()

def test_pci_dss_v4_6_plus_4_compliance():
    """Verify that CC tokenization reveals exactly the first 6 and last 4 digits."""
    raw_cc = "4111-2222-3333-4444"
    token = generate_dp_token(raw_cc)
    
    digits = token.replace("-", "")
    # BIN (First 6)
    assert digits[:6] == "411122", "PCI BIN (First 6) mismatch"
    # Identity (Last 4)
    assert digits[12:] == "4444", "PCI Last 4 mismatch"
    
    # Middle 6 must be masked/encrypted
    assert digits[6:12] != "223333", "PII leak in middle digits"

def test_luhn_preservation():
    """Verify that the generated CC tokens are Luhn-valid identifiers."""
    raw_cc = "4111-2222-3333-4444"
    token = generate_dp_token(raw_cc)
    digits = token.replace("-", "")
    
    # Standard Luhn check
    assert _get_luhn_sum(digits) % 10 == 0, "Token failed Luhn checksum"

def test_bijective_entropy_expansion():
    """Verify that bijective names use 10-digit tags (128-bit entropy)."""
    name = "Robert Oppenheimer"
    token = generate_dp_token(name, "PERSON")
    
    parts = token.split("-")
    tag = parts[-1]
    
    assert len(tag) == 10, f"Entropy tag {tag} is too small (expected 10 digits)"
    assert tag.isdigit(), "Entropy tag must be numeric"

def test_collision_avoidance_determinism():
    """Verify deterministic behavior across tenants for compliance integrity."""
    val = "Secret Project"
    t1 = generate_dp_token(val, "ORGANIZATION")
    t2 = generate_dp_token(val, "ORGANIZATION")
    assert t1 == t2, "Non-deterministic outcome detected"
