"""AirDrop-Zero: Cryptography Module (Phase 2)
Provides AES encryption using cryptography.fernet with deterministic key derivation
from a shared mesh passphrase, and SHA-256 integrity verification.
"""

import base64
import hashlib
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger("crypto")

DEFAULT_PASSPHRASE = "airdrop-zero-mesh-default"
DEFAULT_SALT = b"airdrop-zero-v1-salt-mesh"


def derive_fernet_key(passphrase: str, salt: bytes = DEFAULT_SALT) -> bytes:
    """Derive a deterministic 32-byte URL-safe base64-encoded Fernet key from a passphrase.

    Uses PBKDF2-HMAC-SHA256 with 100,000 iterations.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def calculate_file_sha256(filepath: str, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 hex digest of a file on disk."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


class MeshCrypto:
    """Handles Fernet AES encryption/decryption for mesh chunk streaming."""

    def __init__(
        self,
        passphrase: str = DEFAULT_PASSPHRASE,
        salt: bytes = DEFAULT_SALT,
    ):
        self.passphrase = passphrase
        self.key = derive_fernet_key(passphrase, salt)
        self.fernet = Fernet(self.key)

    def encrypt_chunk(self, data: bytes) -> bytes:
        """Encrypt a binary chunk with AES-128-CBC + HMAC-SHA256."""
        return self.fernet.encrypt(data)

    def decrypt_chunk(self, token: bytes) -> bytes:
        """Decrypt an encrypted chunk.

        Raises:
            InvalidToken: If key does not match or chunk has been tampered with.
        """
        return self.fernet.decrypt(token)

    @staticmethod
    def calculate_sha256(filepath: str) -> str:
        return calculate_file_sha256(filepath)
