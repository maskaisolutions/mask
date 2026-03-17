"""Tests for expanded regex patterns added in v0.4.0."""

import re
import pytest

from mask_privacy.core.scanner import REGEX_PATTERNS, PresidioScanner


class TestInternationalPhonePatterns:
    """PHONE_NUMBER_INTL should match UK, French, and German phone numbers."""

    @pytest.mark.parametrize("number", [
        "+44 20 7946 0958",
        "+44 7911 123456",
        "+442079460958",
        "+33 1 23 45 67 89",
        "+33 6 12 34 56 78",
        "+49 30 1234 5678",
        "+49 170 1234567",
    ])
    def test_intl_phone_match(self, number):
        pattern = REGEX_PATTERNS["PHONE_NUMBER_INTL"]
        assert pattern.search(number), f"Expected match for: {number}"

    @pytest.mark.parametrize("non_match", [
        "+1 555 123 4567",     # US number — should NOT match INTL pattern
        "020 7946 0958",       # No country code
        "just some text",
    ])
    def test_intl_phone_no_match(self, non_match):
        pattern = REGEX_PATTERNS["PHONE_NUMBER_INTL"]
        assert not pattern.search(non_match), f"Unexpected match for: {non_match}"


class TestUSRoutingNumber:
    """US_ROUTING_NUMBER regex and ABA checksum."""

    def test_regex_matches_9_digit_number(self):
        pattern = REGEX_PATTERNS["US_ROUTING_NUMBER"]
        assert pattern.search("021000021")  # Chase NYC routing number

    def test_regex_does_not_match_8_digits(self):
        pattern = REGEX_PATTERNS["US_ROUTING_NUMBER"]
        # \b boundaries mean 8 digits surrounded by non-word won't match
        assert not pattern.search("word 12345678 word")

    def test_aba_checksum_valid(self):
        # 021000021 is the real JPMorgan Chase routing number
        assert PresidioScanner._aba_checksum("021000021") is True

    def test_aba_checksum_invalid(self):
        assert PresidioScanner._aba_checksum("123456789") is False

    def test_aba_checksum_wrong_length(self):
        assert PresidioScanner._aba_checksum("12345") is False


class TestUSPassport:
    """US_PASSPORT: 1 uppercase letter + 8 digits."""

    @pytest.mark.parametrize("passport", [
        "C12345678",
        "A00000001",
        "Z99999999",
    ])
    def test_passport_match(self, passport):
        pattern = REGEX_PATTERNS["US_PASSPORT"]
        assert pattern.search(passport), f"Expected match for: {passport}"

    @pytest.mark.parametrize("non_match", [
        "c12345678",   # lowercase letter
        "12345678A",   # letter at end
        "AB12345678",  # two letters
        "A1234567",    # only 7 digits
    ])
    def test_passport_no_match(self, non_match):
        pattern = REGEX_PATTERNS["US_PASSPORT"]
        assert not pattern.search(non_match), f"Unexpected match for: {non_match}"


class TestDateOfBirth:
    """DATE_OF_BIRTH: MM/DD/YYYY and YYYY-MM-DD."""

    @pytest.mark.parametrize("dob", [
        "01/15/1990",
        "12/31/2000",
        "06/01/1985",
        "1990-01-15",
        "2000-12-31",
        "1985-06-01",
    ])
    def test_dob_match(self, dob):
        pattern = REGEX_PATTERNS["DATE_OF_BIRTH"]
        assert pattern.search(dob), f"Expected match for: {dob}"

    @pytest.mark.parametrize("non_match", [
        "13/01/1990",   # month 13
        "00/15/1990",   # month 00
        "01/32/1990",   # day 32
        "1890-01-01",   # year 1890 (only 19xx/20xx)
        "2100-01-01",   # year 2100
    ])
    def test_dob_no_match(self, non_match):
        pattern = REGEX_PATTERNS["DATE_OF_BIRTH"]
        assert not pattern.search(non_match), f"Unexpected match for: {non_match}"
