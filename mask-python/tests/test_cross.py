import os
os.environ["MASK_ENCRYPTION_KEY"] = "my-test-secret-key-1234567890"

from mask_privacy.core.crypto import get_crypto_engine
engine = get_crypto_engine()

plaintext = "Hello from Python"
ciphertext = engine.encrypt(plaintext)
print(f"PYTHON ENCRYPTED: {ciphertext}")
