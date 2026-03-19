"""Tests for the custom exception hierarchy."""

from mask_privacy.core.exceptions import (
    MaskError,
    MaskVaultConnectionError,
    MaskDecryptionError,
    MaskNLPTimeout,
)


class TestExceptionHierarchy:
    """All custom exceptions inherit from MaskError."""

    def test_mask_error_is_exception(self):
        assert issubclass(MaskError, Exception)

    def test_vault_connection_error_inherits(self):
        assert issubclass(MaskVaultConnectionError, MaskError)

    def test_decryption_error_inherits(self):
        assert issubclass(MaskDecryptionError, MaskError)

    def test_nlp_timeout_inherits(self):
        assert issubclass(MaskNLPTimeout, MaskError)




class TestExceptionRaiseCatch:
    """Verify raise/catch semantics work as expected."""

    def test_catch_vault_error_as_mask_error(self):
        with __import__("pytest").raises(MaskError):
            raise MaskVaultConnectionError("redis down")

    def test_catch_decryption_error_as_mask_error(self):
        with __import__("pytest").raises(MaskError):
            raise MaskDecryptionError("bad key")

    def test_catch_nlp_timeout_as_mask_error(self):
        with __import__("pytest").raises(MaskError):
            raise MaskNLPTimeout("took too long")



    def test_specific_catch_does_not_catch_sibling(self):
        import pytest
        with pytest.raises(MaskDecryptionError):
            raise MaskDecryptionError("bad key")
        # MaskVaultConnectionError should NOT be caught by MaskDecryptionError
        with pytest.raises(MaskVaultConnectionError):
            raise MaskVaultConnectionError("redis gone")


class TestExceptionsExportedFromPackage:
    """Exceptions should be importable from the top-level mask package."""

    def test_import_from_mask(self):
        import mask_privacy
        assert hasattr(mask_privacy, "MaskError")
        assert hasattr(mask_privacy, "MaskVaultConnectionError")
        assert hasattr(mask_privacy, "MaskDecryptionError")
        assert hasattr(mask_privacy, "MaskNLPTimeout")
