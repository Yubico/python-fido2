# coding=utf-8

# Copyright (c) 2013 Yubico AB
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

import mock
import unittest
from threading import Event, Timer
from binascii import a2b_hex
from fido2.utils import sha256, websafe_decode
from fido2.hid import CAPABILITY
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError, APDU, RegistrationData, SignatureData
from fido2.ctap2 import Info, AttestationObject
from fido2.client import ClientData, U2fClient, ClientError, Fido2Client
from fido2.webauthn import PublicKeyCredentialCreationOptions


class TestClientData(unittest.TestCase):
    def test_client_data(self):
        client_data = ClientData(
            b'{"typ":"navigator.id.finishEnrollment","challenge":"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo","cid_pubkey":{"kty":"EC","crv":"P-256","x":"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8","y":"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4"},"origin":"http://example.com"}'  # noqa E501
        )

        self.assertEqual(
            client_data.hash,
            a2b_hex("4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb"),
        )
        self.assertEqual(client_data.get("origin"), "http://example.com")

        self.assertEqual(client_data, ClientData.from_b64(client_data.b64))

        self.assertEqual(
            client_data.data,
            {
                "typ": "navigator.id.finishEnrollment",
                "challenge": "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo",
                "cid_pubkey": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8",
                    "y": "XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4",
                },
                "origin": "http://example.com",
            },
        )


APP_ID = "https://foo.example.com"
REG_DATA = RegistrationData(
    a2b_hex(
        b"0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871"  # noqa E501
    )
)
SIG_DATA = SignatureData(
    a2b_hex(
        b"0100000001304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272ec10047a923f"  # noqa E501
    )
)


class TestU2fClient(unittest.TestCase):
    def test_register_wrong_app_id(self):
        client = U2fClient(None, APP_ID)
        try:
            client.register(
                "https://bar.example.com",
                [{"version": "U2F_V2", "challenge": "foobar"}],
                [],
            )
            self.fail("register did not raise error")
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.BAD_REQUEST)

    def test_register_unsupported_version(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = "U2F_XXX"

        try:
            client.register(APP_ID, [{"version": "U2F_V2", "challenge": "foobar"}], [])
            self.fail("register did not raise error")
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.DEVICE_INELIGIBLE)

        client.ctap.get_version.assert_called_with()

    def test_register_existing_key(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = "U2F_V2"
        client.ctap.authenticate.side_effect = ApduError(APDU.USE_NOT_SATISFIED)

        try:
            client.register(
                APP_ID,
                [{"version": "U2F_V2", "challenge": "foobar"}],
                [{"version": "U2F_V2", "keyHandle": "a2V5"}],
            )
            self.fail("register did not raise error")
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.DEVICE_INELIGIBLE)

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called_once()
        # Check keyHandle
        self.assertEqual(client.ctap.authenticate.call_args[0][2], b"key")
        # Ensure check-only was set
        self.assertTrue(client.ctap.authenticate.call_args[0][3])

    def test_register(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = "U2F_V2"
        client.ctap.authenticate.side_effect = ApduError(APDU.WRONG_DATA)
        client.ctap.register.return_value = REG_DATA

        resp = client.register(
            APP_ID,
            [{"version": "U2F_V2", "challenge": "foobar"}],
            [{"version": "U2F_V2", "keyHandle": "a2V5"}],
        )

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called_once()
        client.ctap.register.assert_called_once()

        client_param, app_param = client.ctap.register.call_args[0]
        self.assertEqual(sha256(websafe_decode(resp["clientData"])), client_param)
        self.assertEqual(websafe_decode(resp["registrationData"]), REG_DATA)
        self.assertEqual(sha256(APP_ID.encode()), app_param)

    def test_register_await_timeout(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = "U2F_V2"
        client.ctap.authenticate.side_effect = ApduError(APDU.WRONG_DATA)
        client.ctap.register.side_effect = ApduError(APDU.USE_NOT_SATISFIED)

        client.poll_delay = 0.01
        event = Event()
        timer = Timer(0.1, event.set)
        timer.start()
        try:
            client.register(
                APP_ID,
                [{"version": "U2F_V2", "challenge": "foobar"}],
                [{"version": "U2F_V2", "keyHandle": "a2V5"}],
                event=event,
            )
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.TIMEOUT)

    def test_register_await_touch(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = "U2F_V2"
        client.ctap.authenticate.side_effect = ApduError(APDU.WRONG_DATA)
        client.ctap.register.side_effect = [
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            REG_DATA,
        ]

        event = Event()
        event.wait = mock.MagicMock()
        resp = client.register(
            APP_ID,
            [{"version": "U2F_V2", "challenge": "foobar"}],
            [{"version": "U2F_V2", "keyHandle": "a2V5"}],
            event=event,
        )

        event.wait.assert_called()

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called_once()
        client.ctap.register.assert_called()

        client_param, app_param = client.ctap.register.call_args[0]
        self.assertEqual(sha256(websafe_decode(resp["clientData"])), client_param)
        self.assertEqual(websafe_decode(resp["registrationData"]), REG_DATA)
        self.assertEqual(sha256(APP_ID.encode()), app_param)

    def test_sign_wrong_app_id(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = "U2F_V2"

        try:
            client.sign(
                "http://foo.example.com",
                "challenge",
                [{"version": "U2F_V2", "keyHandle": "a2V5"}],
            )
            self.fail("sign did not raise error")
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.BAD_REQUEST)

    def test_sign_unsupported_version(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = "U2F_XXX"

        try:
            client.sign(
                APP_ID, "challenge", [{"version": "U2F_V2", "keyHandle": "a2V5"}]
            )
            self.fail("sign did not raise error")
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.DEVICE_INELIGIBLE)

        client.ctap.get_version.assert_called_with()

    def test_sign_missing_key(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = "U2F_V2"
        client.ctap.authenticate.side_effect = ApduError(APDU.WRONG_DATA)

        try:
            client.sign(
                APP_ID, "challenge", [{"version": "U2F_V2", "keyHandle": "a2V5"}]
            )
            self.fail("sign did not raise error")
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.DEVICE_INELIGIBLE)

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called_once()
        _, app_param, key_handle = client.ctap.authenticate.call_args[0]
        self.assertEqual(app_param, sha256(APP_ID.encode()))
        self.assertEqual(key_handle, b"key")

    def test_sign(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = "U2F_V2"
        client.ctap.authenticate.return_value = SIG_DATA

        resp = client.sign(
            APP_ID, "challenge", [{"version": "U2F_V2", "keyHandle": "a2V5"}]
        )

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called_once()
        client_param, app_param, key_handle = client.ctap.authenticate.call_args[0]

        self.assertEqual(client_param, sha256(websafe_decode(resp["clientData"])))
        self.assertEqual(app_param, sha256(APP_ID.encode()))
        self.assertEqual(key_handle, b"key")
        self.assertEqual(websafe_decode(resp["signatureData"]), SIG_DATA)

    def test_sign_await_touch(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = "U2F_V2"
        client.ctap.authenticate.side_effect = [
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            SIG_DATA,
        ]

        event = Event()
        event.wait = mock.MagicMock()

        resp = client.sign(
            APP_ID,
            "challenge",
            [{"version": "U2F_V2", "keyHandle": "a2V5"}],
            event=event,
        )

        event.wait.assert_called()

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called()
        client_param, app_param, key_handle = client.ctap.authenticate.call_args[0]

        self.assertEqual(client_param, sha256(websafe_decode(resp["clientData"])))
        self.assertEqual(app_param, sha256(APP_ID.encode()))
        self.assertEqual(key_handle, b"key")
        self.assertEqual(websafe_decode(resp["signatureData"]), SIG_DATA)


rp = {"id": "example.com", "name": "Example RP"}
user = {"id": b"user_id", "name": "A. User"}
challenge = b"Y2hhbGxlbmdl"
_INFO_NO_PIN = a2b_hex(
    "a60182665532465f5632684649444f5f325f3002826375766d6b686d61632d7365637265740350f8a011f38c0a4d15800617111f9edc7d04a462726bf5627570f564706c6174f469636c69656e7450696ef4051904b0068101"  # noqa E501
)
_MC_RESP = a2b_hex(
    "a301667061636b6564025900c40021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12410000001cf8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a529003a363616c67266373696758483046022100cc1ef43edf07de8f208c21619c78a565ddcf4150766ad58781193be8e0a742ed022100f1ed7c7243e45b7d8e5bda6b1abf10af7391789d1ef21b70bd69fed48dba4cb163783563815901973082019330820138a003020102020900859b726cb24b4c29300a06082a8648ce3d0403023047310b300906035504061302555331143012060355040a0c0b59756269636f205465737431223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e301e170d3136313230343131353530305a170d3236313230323131353530305a3047310b300906035504061302555331143012060355040a0c0b59756269636f205465737431223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3059301306072a8648ce3d020106082a8648ce3d03010703420004ad11eb0e8852e53ad5dfed86b41e6134a18ec4e1af8f221a3c7d6e636c80ea13c3d504ff2e76211bb44525b196c44cb4849979cf6f896ecd2bb860de1bf4376ba30d300b30090603551d1304023000300a06082a8648ce3d0403020349003046022100e9a39f1b03197525f7373e10ce77e78021731b94d0c03f3fda1fd22db3d030e7022100c4faec3445a820cf43129cdb00aabefd9ae2d874f9c5d343cb2f113da23723f3"  # noqa E501
)


class TestFido2Client(unittest.TestCase):
    def test_ctap1_info(self):
        dev = mock.Mock()
        dev.capabilities = 0
        client = Fido2Client(dev, APP_ID)
        self.assertEqual(client.info.versions, ["U2F_V2"])
        self.assertEqual(client.info.pin_uv_protocols, [])

    @mock.patch("fido2.client.CTAP2")
    def test_make_credential_wrong_app_id(self, PatchedCTAP2):
        dev = mock.Mock()
        dev.capabilities = CAPABILITY.CBOR
        ctap2 = mock.MagicMock()
        ctap2.get_info.return_value = Info(_INFO_NO_PIN)
        PatchedCTAP2.return_value = ctap2
        client = Fido2Client(dev, APP_ID)
        try:
            client.make_credential(
                PublicKeyCredentialCreationOptions(
                    {"id": "bar.example.com", "name": "Invalid RP"},
                    user,
                    challenge,
                    [{"type": "public-key", "alg": -7}],
                )
            )
            self.fail("make_credential did not raise error")
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.BAD_REQUEST)

    @mock.patch("fido2.client.CTAP2")
    def test_make_credential_existing_key(self, PatchedCTAP2):
        dev = mock.Mock()
        dev.capabilities = CAPABILITY.CBOR
        ctap2 = mock.MagicMock()
        ctap2.get_info.return_value = Info(_INFO_NO_PIN)
        ctap2.make_credential.side_effect = CtapError(CtapError.ERR.CREDENTIAL_EXCLUDED)
        PatchedCTAP2.return_value = ctap2
        client = Fido2Client(dev, APP_ID)

        try:
            client.make_credential(
                PublicKeyCredentialCreationOptions(
                    rp,
                    user,
                    challenge,
                    [{"type": "public-key", "alg": -7}],
                    authenticator_selection={"userVerification": "discouraged"},
                )
            )
            self.fail("make_credential did not raise error")
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.DEVICE_INELIGIBLE)

        ctap2.get_info.assert_called_with()
        ctap2.make_credential.assert_called_once()

    @mock.patch("fido2.client.CTAP2")
    def test_make_credential_ctap2(self, PatchedCTAP2):
        dev = mock.Mock()
        dev.capabilities = CAPABILITY.CBOR
        ctap2 = mock.MagicMock()
        ctap2.get_info.return_value = Info(_INFO_NO_PIN)
        ctap2.make_credential.return_value = AttestationObject(_MC_RESP)
        PatchedCTAP2.return_value = ctap2
        client = Fido2Client(dev, APP_ID)

        attestation, client_data = client.make_credential(
            PublicKeyCredentialCreationOptions(
                rp,
                user,
                challenge,
                [{"type": "public-key", "alg": -7}],
                timeout=1000,
                authenticator_selection={"userVerification": "discouraged"},
            )
        )

        self.assertIsInstance(attestation, AttestationObject)
        self.assertIsInstance(client_data, ClientData)

        ctap2.get_info.assert_called_with()
        ctap2.make_credential.assert_called_with(
            client_data.hash,
            rp,
            user,
            [{"type": "public-key", "alg": -7}],
            None,
            None,
            None,
            None,
            None,
            mock.ANY,
            None,
        )

        self.assertEqual(client_data.get("origin"), APP_ID)
        self.assertEqual(client_data.get("type"), "webauthn.create")
        self.assertEqual(client_data.challenge, challenge)

    def test_make_credential_ctap1(self):
        dev = mock.Mock()
        dev.capabilities = 0  # No CTAP2
        client = Fido2Client(dev, APP_ID)

        client.ctap1 = mock.MagicMock()
        client.ctap1.get_version.return_value = "U2F_V2"
        client.ctap1.register.return_value = REG_DATA

        attestation, client_data = client.make_credential(
            PublicKeyCredentialCreationOptions(
                rp, user, challenge, [{"type": "public-key", "alg": -7}]
            )
        )

        self.assertIsInstance(attestation, AttestationObject)
        self.assertIsInstance(client_data, ClientData)

        client.ctap1.register.assert_called_with(
            client_data.hash, sha256(rp["id"].encode())
        )

        self.assertEqual(client_data.get("origin"), APP_ID)
        self.assertEqual(client_data.get("type"), "webauthn.create")
        self.assertEqual(client_data.challenge, challenge)

        self.assertEqual(attestation.fmt, "fido-u2f")
