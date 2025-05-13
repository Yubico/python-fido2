# Copyright (c) 2019 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import json
import unittest

from fido2.utils import websafe_encode
from fido2.webauthn import (
    Aaguid,
    AuthenticatorSelectionCriteria,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
)


class TestAaguid(unittest.TestCase):
    def test_aaguid(self):
        bs = b"\1" * 16
        a = Aaguid(bs)
        assert a
        assert a == bs
        assert bs == a

    def test_aaguid_none(self):
        a = Aaguid(b"\0" * 16)
        assert not a
        assert a == Aaguid.NONE
        assert Aaguid.NONE == a

    def test_aaguid_wrong_length(self):
        with self.assertRaises(ValueError):
            Aaguid(b"1234")

        with self.assertRaises(ValueError):
            Aaguid.fromhex("11" * 15)

        with self.assertRaises(ValueError):
            Aaguid(b"\2" * 17)

    def test_aaguid_parse(self):
        a = Aaguid.parse("00000000-0000-0000-0000-000000000000")
        assert a == Aaguid.NONE

        b = Aaguid.parse("01020304-0102-0304-0506-010203040506")
        assert b == Aaguid.fromhex("01020304010203040506010203040506")
        assert b == Aaguid(bytes.fromhex("01020304010203040506010203040506"))


class TestWebAuthnDataTypes(unittest.TestCase):
    def test_collected_client_data(self):
        o = CollectedClientData(
            b'{"type":"webauthn.create","challenge":"cdySOP-1JI4J_BpOeO9ut25rlZJueF16aO6auTTYAis","origin":"https://demo.yubico.com","crossOrigin":false}'  # noqa
        )

        assert o.type == "webauthn.create"
        assert o.origin == "https://demo.yubico.com"
        assert o.challenge == bytes.fromhex(
            "71dc9238ffb5248e09fc1a4e78ef6eb76e6b95926e785d7a68ee9ab934d8022b"
        )
        assert o.cross_origin is False

        assert (
            o.b64
            == "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY2R5U09QLTFKSTRKX0JwT2VPOXV0MjVybFpKdWVGMTZhTzZhdVRUWUFpcyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"  # noqa
        )
        assert o.hash == bytes.fromhex(
            "8b20a0b904b4747aacae71d55bf60b4eb2583f7e639f55f40baac23c2600c178"
        )

        assert o == CollectedClientData.create(
            "webauthn.create",
            "cdySOP-1JI4J_BpOeO9ut25rlZJueF16aO6auTTYAis",
            "https://demo.yubico.com",
        )

        o = CollectedClientData.create(
            "webauthn.create",
            "cdySOP-1JI4J_BpOeO9ut25rlZJueF16aO6auTTYAis",
            "https://demo.yubico.com",
            True,
        )
        assert o.cross_origin is True

    def test_authenticator_selection_criteria(self):
        o = AuthenticatorSelectionCriteria(
            authenticator_attachment="platform",
            require_resident_key=True,
            user_verification="required",
        )
        self.assertEqual(
            dict(o),
            {
                "authenticatorAttachment": "platform",
                "requireResidentKey": True,
                "residentKey": "required",
                "userVerification": "required",
            },
        )
        self.assertEqual(o.authenticator_attachment, "platform")
        self.assertEqual(o.require_resident_key, True)
        self.assertEqual(o.user_verification, "required")

        self.assertIsNone(
            AuthenticatorSelectionCriteria(
                authenticator_attachment="invalid"
            ).authenticator_attachment
        )

        self.assertIsNone(
            AuthenticatorSelectionCriteria(
                user_verification="invalid"
            ).user_verification
        )

        self.assertEqual(
            AuthenticatorSelectionCriteria(resident_key="invalid").resident_key,
            "discouraged",
        )

        o = AuthenticatorSelectionCriteria()
        self.assertEqual(o.resident_key, "discouraged")
        self.assertEqual(o.require_resident_key, False)
        self.assertIsNone(o.authenticator_attachment)
        self.assertIsNone(o.user_verification)

        o = AuthenticatorSelectionCriteria(require_resident_key=True)
        self.assertEqual(o.resident_key, ResidentKeyRequirement.REQUIRED)
        self.assertEqual(o.require_resident_key, True)

        o = AuthenticatorSelectionCriteria(resident_key=False)
        self.assertEqual(o.require_resident_key, False)

        o = AuthenticatorSelectionCriteria(resident_key="required")
        self.assertEqual(o.resident_key, ResidentKeyRequirement.REQUIRED)
        self.assertEqual(o.require_resident_key, True)

        o = AuthenticatorSelectionCriteria(resident_key="preferred")
        self.assertEqual(o.resident_key, ResidentKeyRequirement.PREFERRED)
        self.assertEqual(o.require_resident_key, False)

        o = AuthenticatorSelectionCriteria(resident_key="discouraged")
        self.assertEqual(o.resident_key, ResidentKeyRequirement.DISCOURAGED)
        self.assertEqual(o.require_resident_key, False)

    def test_rp_entity(self):
        o = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        self.assertEqual(o, {"id": "example.com", "name": "Example"})
        self.assertEqual(o.id, "example.com")
        self.assertEqual(o.name, "Example")

        with self.assertRaises(TypeError):
            PublicKeyCredentialRpEntity(id="example.com")

        with self.assertRaises(TypeError):
            PublicKeyCredentialRpEntity()

    def test_user_entity(self):
        o = PublicKeyCredentialUserEntity(
            name="Example", id=b"user", display_name="Display"
        )
        self.assertEqual(
            o,
            {
                "id": websafe_encode(b"user"),
                "name": "Example",
                "displayName": "Display",
            },
        )
        self.assertEqual(o.id, b"user")
        self.assertEqual(o.name, "Example")
        self.assertEqual(o.display_name, "Display")

        with self.assertRaises(TypeError):
            PublicKeyCredentialUserEntity(name=b"user")

        with self.assertRaises(TypeError):
            PublicKeyCredentialUserEntity()

    def test_parameters(self):
        o = PublicKeyCredentialParameters(type="public-key", alg=-7)
        self.assertEqual(o, {"type": "public-key", "alg": -7})
        self.assertEqual(o.type, "public-key")
        self.assertEqual(o.alg, -7)

        p = PublicKeyCredentialParameters(type="invalid-type", alg=-7)
        assert p.type is None

        with self.assertRaises(TypeError):
            PublicKeyCredentialParameters("public-key")

        with self.assertRaises(TypeError):
            PublicKeyCredentialParameters()

    def test_descriptor(self):
        o = PublicKeyCredentialDescriptor(type="public-key", id=b"credential_id")
        self.assertEqual(
            o, {"type": "public-key", "id": websafe_encode(b"credential_id")}
        )
        self.assertEqual(o.type, "public-key")
        self.assertEqual(o.id, b"credential_id")
        self.assertIsNone(o.transports)

        o = PublicKeyCredentialDescriptor(
            type="public-key", id=b"credential_id", transports=["usb", "nfc"]
        )
        self.assertEqual(
            o,
            {
                "type": "public-key",
                "id": websafe_encode(b"credential_id"),
                "transports": ["usb", "nfc"],
            },
        )
        self.assertEqual(o.transports, ["usb", "nfc"])

        PublicKeyCredentialDescriptor(
            type="public-key", id=b"credential_id", transports=["valid_value"]
        )

        d = PublicKeyCredentialDescriptor(type="wrong-type", id=b"credential_id")
        assert d.type is None

        with self.assertRaises(TypeError):
            PublicKeyCredentialDescriptor(type="public-key")

        with self.assertRaises(TypeError):
            PublicKeyCredentialDescriptor()

    def test_creation_options(self):
        o = PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(id="example.com", name="Example"),
            user=PublicKeyCredentialUserEntity(id=b"user_id", name="A. User"),
            challenge=b"request_challenge",
            pub_key_cred_params=[{"type": "public-key", "alg": -7}],
            timeout=10000,
            exclude_credentials=[{"type": "public-key", "id": b"credential_id"}],
            authenticator_selection={
                "authenticatorAttachment": "platform",
                "residentKey": "required",
                "userVerification": "required",
            },
            attestation="direct",
        )
        self.assertEqual(o.rp, {"id": "example.com", "name": "Example"})
        self.assertEqual(o.user, {"id": websafe_encode(b"user_id"), "name": "A. User"})
        self.assertIsNone(o.extensions)

        js = json.dumps(dict(o))
        o2 = PublicKeyCredentialCreationOptions.from_dict(json.loads(js))
        self.assertEqual(o, o2)

        o = PublicKeyCredentialCreationOptions.from_dict(
            {
                "rp": {"id": "example.com", "name": "Example"},
                "user": {"id": websafe_encode(b"user_id"), "name": "A. User"},
                "challenge": websafe_encode(b"request_challenge"),
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            }
        )
        self.assertEqual(o.user.id, b"user_id")
        self.assertEqual(o.challenge, b"request_challenge")
        self.assertIsNone(o.timeout)
        self.assertIsNone(o.authenticator_selection)
        self.assertIsNone(o.attestation)

        self.assertIsNone(
            PublicKeyCredentialCreationOptions(
                rp={"id": "example.com", "name": "Example"},
                user={"id": b"user_id", "name": "A. User"},
                challenge=b"request_challenge",
                pub_key_cred_params=[{"type": "public-key", "alg": -7}],
                attestation="invalid",
            ).attestation
        )

        js = json.dumps(dict(o))
        o2 = PublicKeyCredentialCreationOptions.from_dict(json.loads(js))

        self.assertEqual(o, o2)

    def test_request_options(self):
        o = PublicKeyCredentialRequestOptions(
            challenge=b"request_challenge",
            timeout=10000,
            rp_id="example.com",
            allow_credentials=[
                PublicKeyCredentialDescriptor(type="public-key", id=b"credential_id")
            ],
            user_verification="discouraged",
        )
        self.assertEqual(o.challenge, b"request_challenge")
        self.assertEqual(o.rp_id, "example.com")
        self.assertEqual(o.timeout, 10000)
        self.assertIsNone(o.extensions)

        js = json.dumps(dict(o))
        o2 = PublicKeyCredentialRequestOptions.from_dict(json.loads(js))
        self.assertEqual(o, o2)

        o = PublicKeyCredentialRequestOptions(challenge=b"request_challenge")
        self.assertIsNone(o.timeout)
        self.assertIsNone(o.rp_id)
        self.assertIsNone(o.allow_credentials)
        self.assertIsNone(o.user_verification)

        self.assertIsNone(
            PublicKeyCredentialRequestOptions(
                challenge=b"request_challenge", user_verification="invalid"
            ).user_verification
        )
