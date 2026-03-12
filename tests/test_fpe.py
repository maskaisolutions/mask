"""Tests for Format-Preserving Encryption token generation."""

import os
import re

import pytest

from mask.core.fpe import generate_fpe_token, looks_like_token, reset_master_key


@pytest.fixture(autouse=True)
def _stable_key(monkeypatch):
    """Use a fixed master key so tests are repeatable."""
    reset_master_key()
    monkeypatch.setenv("MASK_MASTER_KEY", "test-key-for-deterministic-fpe")
    yield
    reset_master_key()


class TestFPETokenGeneration:
    def test_email_format(self):
        token = generate_fpe_token("user@company.io")
        assert token.endswith("@email.com")
        assert token.startswith("tkn-")
        # Must pass a standard email regex
        assert re.match(r"^[^@]+@[^@]+\.[^@]+$", token)

    def test_phone_format(self):
        token = generate_fpe_token("+1-212-555-1234")
        assert token.startswith("+1-555-")
        assert len(token) == 14
        # Must look like a phone number
        assert re.match(r"^\+1-555-\d{7}$", token)

    def test_seven_digit_phone_format(self):
        """Regression test for the 7-digit phone leak fix."""
        token = generate_fpe_token("555-1234")
        assert token.startswith("+1-555-")
        assert len(token) == 14

    def test_ssn_format(self):
        token = generate_fpe_token("123-45-6789")
        assert token.startswith("000-00-")
        assert len(token) == 11
        # Must look like an SSN
        assert re.match(r"^\d{3}-\d{2}-\d{4}$", token)

    def test_cc_format(self):
        token = generate_fpe_token("4111-1111-1111-1111")
        assert token.startswith("4000-0000-0000-")
        assert len(token) == 19
        assert re.match(r"^(?:\d{4}[ \-]?){3}\d{4}$", token)

    def test_routing_format(self):
        token = generate_fpe_token("122000661")
        assert token.startswith("000000")
        assert len(token) == 9
        assert re.match(r"^\d{9}$", token)

    def test_opaque_fallback(self):
        token = generate_fpe_token("just some random string")
        assert token.startswith("[TKN-")
        assert token.endswith("]")

    def test_deterministic_same_input_same_output(self):
        """Same input MUST produce the same token (deterministic HMAC)."""
        t1 = generate_fpe_token("a@b.com")
        t2 = generate_fpe_token("a@b.com")
        assert t1 == t2
        assert t1.endswith("@email.com")

    def test_different_inputs_different_tokens(self):
        """Different inputs must produce different tokens."""
        t1 = generate_fpe_token("alice@example.com")
        t2 = generate_fpe_token("bob@example.com")
        assert t1 != t2

    def test_determinism_across_all_types(self):
        """Verify determinism for every supported format."""
        for value in [
            "user@test.com",
            "+1-212-555-1234",
            "555-1234",
            "123-45-6789",
            "4111-1111-1111-1111",
            "122000661",
            "John Doe",
        ]:
            assert generate_fpe_token(value) == generate_fpe_token(value)


class TestLooksLikeToken:
    def test_email_token(self):
        assert looks_like_token("tkn-abcd1234@email.com") is True

    def test_phone_token(self):
        assert looks_like_token("+1-555-1234567") is True

    def test_ssn_token(self):
        assert looks_like_token("000-00-1234") is True

    def test_cc_token(self):
        assert looks_like_token("4000-0000-0000-1234") is True

    def test_routing_token(self):
        assert looks_like_token("000000123") is True

    def test_opaque_token(self):
        assert looks_like_token("[TKN-abcd1234]") is True

    def test_real_email_is_not_token(self):
        assert looks_like_token("real@company.com") is False

    def test_random_string_is_not_token(self):
        assert looks_like_token("hello world") is False
