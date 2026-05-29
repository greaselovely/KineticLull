"""
Fernet-based at-rest encryption for AppSettings secrets.

The key is derived from Django's SECRET_KEY via SHA-256, so rotating SECRET_KEY
will invalidate existing ciphertexts. SECRET_KEY lives in .env, which is excluded
from git and survives DB wipes.
"""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import models


_ENCRYPTED_PREFIX = 'enc:v1:'


def _fernet():
    digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(value: str) -> str:
    if not value:
        return value
    if value.startswith(_ENCRYPTED_PREFIX):
        return value
    token = _fernet().encrypt(value.encode()).decode()
    return _ENCRYPTED_PREFIX + token


def decrypt(value: str) -> str:
    if not value:
        return value
    if not value.startswith(_ENCRYPTED_PREFIX):
        return value  # legacy plaintext — caller handles upgrade
    try:
        return _fernet().decrypt(value[len(_ENCRYPTED_PREFIX):].encode()).decode()
    except InvalidToken:
        return ''  # unrecoverable (e.g., SECRET_KEY rotated) — return empty


def is_encrypted(value: str) -> bool:
    return bool(value) and value.startswith(_ENCRYPTED_PREFIX)


class EncryptedCharField(models.CharField):
    """CharField that encrypts at rest. Application code sees plaintext."""

    description = 'CharField with Fernet encryption at rest'

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return decrypt(value)

    def to_python(self, value):
        if value is None:
            return value
        return decrypt(value)

    def get_prep_value(self, value):
        if value is None or value == '':
            return value
        return encrypt(value)


class EncryptedTextField(models.TextField):
    """TextField that encrypts at rest. Application code sees plaintext.

    Use for free-text secrets that may be multi-line or longer than a CharField
    (e.g. the One-Time Secret payload).
    """

    description = 'TextField with Fernet encryption at rest'

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return decrypt(value)

    def to_python(self, value):
        if value is None:
            return value
        return decrypt(value)

    def get_prep_value(self, value):
        if value is None or value == '':
            return value
        return encrypt(value)
