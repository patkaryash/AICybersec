"""Password hashing: Argon2id via pwdlib (maintained implementation).

Passwords are never stored plaintext, never logged, never included in
events or API payloads. Only the hash is persisted.
"""
from __future__ import annotations

from pwdlib import PasswordHash

_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return _hasher.verify(password, password_hash)
