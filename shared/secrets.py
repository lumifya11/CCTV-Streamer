"""Encrypted Credential Vault using authenticated AES-GCM / Fernet encryption at rest."""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from shared.config import get_config, is_placeholder_secret
from shared.logger import get_logger

logger = get_logger("shared.secrets")

_VAULT_SALT = b"cctv-streamer-vault-kdf-salt-v1"


def _derive_fernet_key(master_key: str) -> bytes:
    """Derive a 32-byte urlsafe-base64 Fernet key from the master key string."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        master_key.encode("utf-8"),
        _VAULT_SALT,
        iterations=120_000,
        dklen=32,
    )
    return base64.urlsafe_b64encode(dk)


class CredentialVault:
    """
    Encrypts and decrypts camera credentials at rest.
    Never returns plaintext secrets in logs or string representations.
    """

    def __init__(self, master_key: Optional[str] = None) -> None:
        cfg = get_config()
        raw_key = master_key if master_key is not None else cfg.vault_master_key
        if cfg.is_production() and is_placeholder_secret(raw_key):
            raise RuntimeError(
                "VAULT_MASTER_KEY is missing or set to a placeholder in production mode."
            )
        if not raw_key:
            # Ephemeral development/test fallback key
            raw_key = os.getenv(
                "VAULT_MASTER_KEY", "dev-only-ephemeral-vault-master-key-do-not-use-in-prod"
            )
        self._fernet = Fernet(_derive_fernet_key(raw_key))

    def encrypt_secret(self, plaintext: str) -> str:
        """Encrypt a secret string and return an opaque ciphertext token."""
        if plaintext is None:
            return ""
        token = self._fernet.encrypt(plaintext.encode("utf-8"))
        return token.decode("ascii")

    def decrypt_secret(self, ciphertext: str) -> str:
        """Decrypt an encrypted credential token for authorized connection use only."""
        if not ciphertext:
            return ""
        try:
            raw = self._fernet.decrypt(ciphertext.encode("ascii"))
            return raw.decode("utf-8")
        except InvalidToken as exc:
            logger.error("Vault failed to decrypt credential profile (invalid key or corrupted token)")
            raise ValueError("Unable to decrypt credential profile with current vault key") from exc

    def rotate_ciphertext(self, ciphertext: str, new_master_key: str) -> str:
        """Re-encrypt a stored credential under a newly rotated master key."""
        plain = self.decrypt_secret(ciphertext)
        new_vault = CredentialVault(master_key=new_master_key)
        return new_vault.encrypt_secret(plain)
