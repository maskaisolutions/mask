import os

from cryptography.fernet import Fernet


# Ensure all tests run with a stable encryption key so that vault
# round-trips behave consistently across process restarts.
#
# In real deployments, MASK_ENCRYPTION_KEY must be managed by the
# operator (KMS, Vault, etc.). For tests we generate a throwaway key.
os.environ.setdefault("MASK_ENCRYPTION_KEY", Fernet.generate_key().decode("utf-8"))

