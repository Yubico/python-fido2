import unittest
import warnings
from typing import Any, Callable, cast

import pytest

from fido2 import features
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    UserVerificationRequirement,
)

from .test_ctap2 import _ATT_CRED_DATA, _CRED_ID


class TestPublicKeyCredentialRpEntity(unittest.TestCase):
    def test_id_hash(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        rp_id_hash = (
            b"\xa3y\xa6\xf6\xee\xaf\xb9\xa5^7\x8c\x11\x804\xe2u\x1eh/"
            b"\xab\x9f-0\xab\x13\xd2\x12U\x86\xce\x19G"
        )
        self.assertEqual(rp.id_hash, rp_id_hash)


USER = {"id": b"user_id", "name": "A. User"}


class TestFido2Server(unittest.TestCase):
    def test_register_begin_rp(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        request, state = server.register_begin(USER)

        self.assertEqual(
            request["publicKey"]["rp"], {"id": "example.com", "name": "Example"}
        )

    def test_register_begin_custom_challenge(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        challenge = b"1234567890123456"
        request, state = server.register_begin(USER, challenge=challenge)

        self.assertEqual(request["publicKey"]["challenge"], websafe_encode(challenge))

    def test_register_begin_custom_challenge_too_short(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        challenge = b"123456789012345"
        with self.assertRaises(ValueError):
            request, state = server.register_begin(USER, challenge=challenge)

    def test_authenticate_complete_invalid_signature(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        state = {
            "challenge": "GAZPACHO!",
            "user_verification": UserVerificationRequirement.PREFERRED,
        }
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.GET,
            "GAZPACHO!",
            "https://example.com",
        )
        _AUTH_DATA = bytes.fromhex(
            "A379A6F6EEAFB9A55E378C118034E2751E682FAB9F2D30AB13D2125586CE1947010000001D"
        )
        response = AuthenticationResponse(
            raw_id=_CRED_ID,
            response=AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=AuthenticatorData(_AUTH_DATA),
                signature=b"INVALID",
            ),
        )

        with self.assertRaisesRegex(ValueError, "Invalid signature."):
            server.authenticate_complete(
                state,
                [AttestedCredentialData(_ATT_CRED_DATA)],
                response,
            )


@pytest.mark.parametrize("feature_state", [None, False, True])
@pytest.mark.parametrize("method", ["constructor", "register", "authenticate"])
def test_positional_optional_arguments(monkeypatch, feature_state, method):
    monkeypatch.setattr(features.server_kw_only, "_enabled", feature_state)
    rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
    challenge = b"0123456789abcdef"
    extensions = {"credProps": True}
    server = Fido2Server(rp)

    if method == "constructor":
        call = cast(Callable[..., Any], Fido2Server)
        required = (rp,)
        kwargs = {
            "attestation": "direct",
            "verify_origin": lambda origin: origin == "https://example.com",
            "verify_attestation": lambda obj, client_data_hash: None,
        }
    elif method == "register":
        call = cast(Callable[..., Any], server.register_begin)
        required = (USER,)
        kwargs = {
            "credentials": [],
            "resident_key_requirement": "required",
            "user_verification": "required",
            "authenticator_attachment": "cross-platform",
            "challenge": challenge,
            "extensions": extensions,
        }
    else:
        call = cast(Callable[..., Any], server.authenticate_begin)
        required = ([],)
        kwargs = {
            "user_verification": "required",
            "challenge": challenge,
            "extensions": extensions,
        }

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        expected = call(*required, **kwargs)
    assert not caught

    args = (*required, *kwargs.values())
    if feature_state is True:
        with pytest.raises(TypeError, match="must be passed by keyword"):
            call(*args)
        return
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        actual = call(*args)
    if feature_state is None:
        assert len(caught) == 1
        assert caught[0].category is DeprecationWarning
        assert "server_kw_only" in str(caught[0].message)
        assert caught[0].filename == __file__
    else:
        assert not caught
    if method == "constructor":
        assert actual.attestation == expected.attestation
        assert actual._verify is kwargs["verify_origin"]
        assert actual._verify_attestation is kwargs["verify_attestation"]
    else:
        assert actual == expected


@pytest.mark.parametrize("feature_state", [None, False, True])
def test_begin_keyword_options(monkeypatch, feature_state):
    monkeypatch.setattr(features.server_kw_only, "_enabled", feature_state)
    rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
    server = Fido2Server(
        rp, attestation="direct", timeout=30000, allowed_algorithms=[-257, -7]
    )
    hints = ["security-key", "hybrid"]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        registration, state = server.register_begin(
            USER,
            credentials=[],
            user_verification="required",
            hints=hints,
            attestation_formats=["packed", "none"],
        )
        authentication, auth_state = server.authenticate_begin(
            [], user_verification="required", hints=hints
        )
    assert not caught
    assert registration["publicKey"]["hints"] == hints
    assert registration["publicKey"]["attestationFormats"] == ["packed", "none"]
    assert registration["publicKey"]["attestation"] == "direct"
    assert registration["publicKey"]["timeout"] == 30000
    assert registration["publicKey"]["pubKeyCredParams"] == [
        {"type": "public-key", "alg": -257},
        {"type": "public-key", "alg": -7},
    ]
    assert authentication["publicKey"]["hints"] == hints
    assert authentication["publicKey"]["timeout"] == 30000
    assert state["user_verification"] == auth_state["user_verification"] == "required"


def test_invalid_positional_arguments(monkeypatch):
    monkeypatch.setattr(features.server_kw_only, "_enabled", None)
    rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
    server = Fido2Server(rp)
    constructor = cast(Callable[..., Any], Fido2Server)
    register = cast(Callable[..., Any], server.register_begin)
    authenticate = cast(Callable[..., Any], server.authenticate_begin)
    with pytest.raises(TypeError, match="multiple values.*attestation"):
        constructor(rp, None, attestation="none")
    with pytest.raises(TypeError, match="multiple values.*credentials"):
        register(USER, [], credentials=[])
    with pytest.raises(TypeError, match="multiple values.*credentials"):
        authenticate([], credentials=[])
    with pytest.raises(TypeError, match="multiple values.*challenge"):
        authenticate([], None, b"0123456789abcdef", challenge=b"other")
    with pytest.raises(TypeError, match="too many positional arguments"):
        constructor(rp, None, None, None, None)
    with pytest.raises(TypeError, match="too many positional arguments"):
        register(USER, None, None, None, None, None, None, [])
    with pytest.raises(TypeError, match="too many positional arguments"):
        authenticate(None, None, None, None, [])


def test_mixed_positional_and_keyword_options(monkeypatch):
    monkeypatch.setattr(features.server_kw_only, "_enabled", None)
    rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
    server = Fido2Server(rp)
    register = cast(Callable[..., Any], server.register_begin)
    with pytest.warns(DeprecationWarning):
        options, state = register(
            USER,
            [],
            user_verification="required",
            hints=["security-key"],
            attestation_formats=["packed"],
        )
    assert options["publicKey"]["excludeCredentials"] == []
    assert options["publicKey"]["hints"] == ["security-key"]
    assert options["publicKey"]["attestationFormats"] == ["packed"]
    assert state["user_verification"] == "required"


def test_empty_allowed_algorithms():
    rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
    server = Fido2Server(rp, allowed_algorithms=[])
    with pytest.raises(ValueError, match="Server has no allowed algorithms"):
        server.register_begin(USER)
    options, _ = server.authenticate_begin()
    assert options["publicKey"]["rpId"] == "example.com"


def test_zero_timeout():
    rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
    server = Fido2Server(rp, timeout=0)
    registration, _ = server.register_begin(USER)
    authentication, _ = server.authenticate_begin()
    assert registration["publicKey"]["timeout"] == 0
    assert authentication["publicKey"]["timeout"] == 0


@pytest.mark.parametrize("feature_state", [None, False, True])
@pytest.mark.parametrize(
    "credentials", [None, [], [AttestedCredentialData(_ATT_CRED_DATA)]]
)
def test_authentication_positional_credentials(monkeypatch, feature_state, credentials):
    monkeypatch.setattr(features.server_kw_only, "_enabled", feature_state)
    rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
    server = Fido2Server(rp)
    kwargs = {"challenge": b"0123456789abcdef", "hints": ["security-key"]}
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        actual = server.authenticate_begin(credentials, **kwargs)
        if credentials is None:
            assert actual == server.authenticate_begin(**kwargs)
    assert not caught
    descriptors = actual[0].public_key.allow_credentials
    if credentials is None:
        assert descriptors is None
    else:
        assert descriptors is not None
        assert [d.id for d in descriptors] == [c.credential_id for c in credentials]
