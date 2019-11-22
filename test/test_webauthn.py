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

from __future__ import absolute_import, unicode_literals

from fido2.webauthn import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)

import unittest


class TestWebAuthnDataTypes(unittest.TestCase):
    def test_authenticator_selection_criteria(self):
        o = AuthenticatorSelectionCriteria("platform", True, "required")
        self.assertEqual(
            o,
            {
                "authenticatorAttachment": "platform",
                "requireResidentKey": True,
                "userVerification": "required",
            },
        )
        self.assertEqual(o.authenticator_attachment, "platform")
        self.assertEqual(o.require_resident_key, True)
        self.assertEqual(o.user_verification, "required")

        with self.assertRaises(ValueError):
            AuthenticatorSelectionCriteria(authenticator_attachment="invalid")

        with self.assertRaises(ValueError):
            AuthenticatorSelectionCriteria(user_verification="invalid")

        o = AuthenticatorSelectionCriteria()
        self.assertEqual(o, {})
        self.assertIsNone(o.authenticator_attachment)
        self.assertIsNone(o.require_resident_key)
        self.assertIsNone(o.user_verification)

    def test_rp_entity(self):
        o = PublicKeyCredentialRpEntity("example.com", "Example")
        self.assertEqual(o, {"id": "example.com", "name": "Example"})
        self.assertEqual(o.id, "example.com")
        self.assertEqual(o.name, "Example")
        self.assertIsNone(o.icon)

        with self.assertRaises(TypeError):
            PublicKeyCredentialRpEntity("example.com")

        with self.assertRaises(TypeError):
            PublicKeyCredentialRpEntity()

    def test_user_entity(self):
        o = PublicKeyCredentialUserEntity(b"user", "Example", display_name="Display")
        self.assertEqual(
            o, {"id": b"user", "name": "Example", "displayName": "Display"}
        )
        self.assertEqual(o.id, b"user")
        self.assertEqual(o.name, "Example")
        self.assertEqual(o.display_name, "Display")
        self.assertIsNone(o.icon)

        with self.assertRaises(TypeError):
            PublicKeyCredentialUserEntity(b"user")

        with self.assertRaises(TypeError):
            PublicKeyCredentialUserEntity()

    def test_parameters(self):
        o = PublicKeyCredentialParameters("public-key", -7)
        self.assertEqual(o, {"type": "public-key", "alg": -7})
        self.assertEqual(o.type, "public-key")
        self.assertEqual(o.alg, -7)

        with self.assertRaises(ValueError):
            PublicKeyCredentialParameters("invalid-type", -7)

        with self.assertRaises(TypeError):
            PublicKeyCredentialParameters("public-key")

        with self.assertRaises(TypeError):
            PublicKeyCredentialParameters()

    def test_descriptor(self):
        o = PublicKeyCredentialDescriptor("public-key", b"credential_id")
        self.assertEqual(o, {"type": "public-key", "id": b"credential_id"})
        self.assertEqual(o.type, "public-key")
        self.assertEqual(o.id, b"credential_id")
        self.assertIsNone(o.transports)

        o = PublicKeyCredentialDescriptor(
            "public-key", b"credential_id", ["usb", "nfc"]
        )
        self.assertEqual(
            o,
            {
                "type": "public-key",
                "id": b"credential_id",
                "transports": ["usb", "nfc"],
            },
        )
        self.assertEqual(o.transports, ["usb", "nfc"])

        PublicKeyCredentialDescriptor("public-key", b"credential_id", ["valid_value"])

        with self.assertRaises(ValueError):
            PublicKeyCredentialDescriptor("wrong-type", b"credential_id")

        with self.assertRaises(TypeError):
            PublicKeyCredentialDescriptor("wrong-type")

        with self.assertRaises(TypeError):
            PublicKeyCredentialDescriptor()

    def test_creation_options(self):
        o = PublicKeyCredentialCreationOptions(
            {"id": "example.com", "name": "Example"},
            {"id": b"user_id", "name": "A. User"},
            b"request_challenge",
            [{"type": "public-key", "alg": -7}],
            10000,
            [{"type": "public-key", "id": b"credential_id"}],
            {
                "authenticatorAttachment": "platform",
                "requireResidentKey": True,
                "userVerification": "required",
            },
            "direct",
        )
        self.assertEqual(o.rp, {"id": "example.com", "name": "Example"})
        self.assertEqual(o.user, {"id": b"user_id", "name": "A. User"})
        self.assertIsNone(o.extensions)

        o = PublicKeyCredentialCreationOptions(
            {"id": "example.com", "name": "Example"},
            {"id": b"user_id", "name": "A. User"},
            b"request_challenge",
            [{"type": "public-key", "alg": -7}],
        )
        self.assertIsNone(o.timeout)
        self.assertIsNone(o.authenticator_selection)
        self.assertIsNone(o.attestation)

        with self.assertRaises(ValueError):
            PublicKeyCredentialCreationOptions(
                {"id": "example.com", "name": "Example"},
                {"id": b"user_id", "name": "A. User"},
                b"request_challenge",
                [{"type": "public-key", "alg": -7}],
                attestation="invalid",
            )

    def test_request_options(self):
        o = PublicKeyCredentialRequestOptions(
            b"request_challenge",
            10000,
            "example.com",
            [{"type": "public-key", "id": b"credential_id"}],
            "discouraged",
        )
        self.assertEqual(o.challenge, b"request_challenge")
        self.assertEqual(o.rp_id, "example.com")
        self.assertEqual(o.timeout, 10000)
        self.assertIsNone(o.extensions)

        o = PublicKeyCredentialRequestOptions(b"request_challenge")
        self.assertIsNone(o.timeout)
        self.assertIsNone(o.rp_id)
        self.assertIsNone(o.allow_credentials)
        self.assertIsNone(o.user_verification)

        with self.assertRaises(ValueError):
            PublicKeyCredentialRequestOptions(
                b"request_challenge", user_verification="invalid"
            )

    def test_update_value(self):
        o = PublicKeyCredentialRpEntity("example.com", "Example")
        self.assertEqual(o, {"id": "example.com", "name": "Example"})
        self.assertEqual(o.id, "example.com")
        self.assertEqual(o.name, "Example")

        o.id = "new-id.com"
        self.assertEqual(o, {"id": "new-id.com", "name": "Example"})
        self.assertEqual(o.id, "new-id.com")

        o["name"] = "New Name"
        self.assertEqual(o, {"id": "new-id.com", "name": "New Name"})
        self.assertEqual(o.name, "New Name")
