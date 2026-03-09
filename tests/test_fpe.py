"""Tests for Format-Preserving Encryption token generation."""

import re

from mask.core.fpe import generate_fpe_token, looks_like_token


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

    def test_deterministic_format_not_value(self):
        """Same input should produce same format but different tokens (randomised)."""
        t1 = generate_fpe_token("a@b.com")
        t2 = generate_fpe_token("a@b.com")
        assert t1 != t2  # different random hex
        assert t1.endswith("@email.com")
        assert t2.endswith("@email.com")


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
