"""Unit tests: JWT creation and verification (backend.core.jwt)."""
from __future__ import annotations

import jwt
import pytest

from backend.core.config import get_backend_settings
from backend.core.jwt import ALGORITHM, create_access_token, decode_access_token

USER_ID = "11111111-2222-3333-4444-555555555555"


def test_valid_token_round_trip():
    token = create_access_token(USER_ID)
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == USER_ID


def test_claims_are_exactly_sub_iat_exp():
    token = create_access_token(USER_ID)
    payload = decode_access_token(token)
    assert set(payload.keys()) == {"sub", "iat", "exp"}
    assert isinstance(payload["iat"], int)
    assert isinstance(payload["exp"], int)
    assert payload["exp"] > payload["iat"]


def test_expired_token_rejected():
    token = create_access_token(USER_ID, expires_in_s=-1)
    assert decode_access_token(token) is None


def test_malformed_token_rejected():
    assert decode_access_token("not-a-token") is None
    assert decode_access_token("") is None


def test_tampered_signature_rejected():
    token = create_access_token(USER_ID)
    tampered = token[:-3] + ("aaa" if token[-3:] != "aaa" else "bbb")
    assert decode_access_token(tampered) is None


def test_wrong_secret_rejected():
    token = create_access_token(USER_ID)
    settings = get_backend_settings()
    forged = jwt.encode(
        {"sub": USER_ID, "iat": 0, "exp": 99999999999},
        "some-other-secret",
        algorithm=ALGORITHM,
    )
    assert forged != token
    assert decode_access_token(forged) is None


def test_missing_sub_rejected():
    forged = jwt.encode(
        {"iat": 0, "exp": 99999999999}, get_backend_settings().jwt_secret, algorithm=ALGORITHM
    )
    assert decode_access_token(forged) is None


def test_missing_exp_rejected():
    forged = jwt.encode(
        {"sub": USER_ID, "iat": 0}, get_backend_settings().jwt_secret, algorithm=ALGORITHM
    )
    assert decode_access_token(forged) is None


def test_algorithm_confusion_rejected():
    """A token signed with 'none' or another algorithm must not decode."""
    forged = jwt.encode(
        {"sub": USER_ID, "iat": 0, "exp": 99999999999},
        get_backend_settings().jwt_secret,
        algorithm="HS512",
    )
    assert decode_access_token(forged) is None


@pytest.mark.parametrize("bad", ["12345", "['a']", "{'a': 1}", "a.b"])
def test_non_token_strings_rejected(bad):
    assert decode_access_token(bad) is None
