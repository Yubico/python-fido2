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
from threading import Event
from binascii import a2b_hex
from fido_host.utils import sha256, websafe_decode
from fido_host.u2f import ApduError, APDU, RegistrationData, SignatureData
from fido_host.client import ClientData, U2fClient, ClientError


class TestClientData(unittest.TestCase):

    def test_client_data(self):
        client_data = ClientData(b'{"typ":"navigator.id.finishEnrollment","challenge":"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo","cid_pubkey":{"kty":"EC","crv":"P-256","x":"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8","y":"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4"},"origin":"http://example.com"}')  # noqa

        self.assertEqual(client_data.hash, a2b_hex('4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb'))  # noqa
        self.assertEqual(client_data.origin, 'http://example.com')

        self.assertEqual(client_data, ClientData.from_b64(client_data.b64))

        self.assertEqual(client_data.data, {
            'typ': 'navigator.id.finishEnrollment',
            'challenge': 'vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo',
            'cid_pubkey': {
                'kty': 'EC',
                'crv': 'P-256',
                'x': 'HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8',
                'y': 'XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4'
            },
            'origin': 'http://example.com'
        })


APP_ID = 'https://foo.example.com'
REG_DATA = RegistrationData(a2b_hex(b'0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871'))  # noqa
SIG_DATA = SignatureData(a2b_hex(b'0100000001304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272ec10047a923f'))  # noqa


class TestU2fClient(unittest.TestCase):

    def test_register_wrong_app_id(self):
        client = U2fClient(None, APP_ID)
        try:
            client.register(
                'https://bar.example.com',
                [{'version': 'U2F_V2', 'challenge': 'foobar'}],
                [],
                timeout=1)
            self.fail('register did not raise error')
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.BAD_REQUEST)

    def test_register_unsupported_version(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = 'U2F_XXX'

        try:
            client.register(
                APP_ID, [{'version': 'U2F_V2', 'challenge': 'foobar'}], [],
                timeout=1)
            self.fail('register did not raise error')
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.DEVICE_INELIGIBLE)

        client.ctap.get_version.assert_called_with()

    def test_register_existing_key(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = 'U2F_V2'
        client.ctap.authenticate.side_effect = ApduError(APDU.USE_NOT_SATISFIED)

        try:
            client.register(
                APP_ID, [{'version': 'U2F_V2', 'challenge': 'foobar'}],
                [{'version': 'U2F_V2', 'keyHandle': 'a2V5'}],
                timeout=1)
            self.fail('register did not raise error')
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.DEVICE_INELIGIBLE)

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called_once()
        # Check keyHandle
        self.assertEqual(client.ctap.authenticate.call_args[0][2], b'key')
        # Ensure check-only was set
        self.assertTrue(client.ctap.authenticate.call_args[0][3])

    def test_register(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = 'U2F_V2'
        client.ctap.authenticate.side_effect = ApduError(APDU.WRONG_DATA)
        client.ctap.register.return_value = REG_DATA

        resp = client.register(
            APP_ID, [{'version': 'U2F_V2', 'challenge': 'foobar'}],
            [{'version': 'U2F_V2', 'keyHandle': 'a2V5'}]
        )

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called_once()
        client.ctap.register.assert_called_once()

        client_param, app_param = client.ctap.register.call_args[0]
        self.assertEqual(sha256(websafe_decode(resp['clientData'])),
                         client_param)
        self.assertEqual(websafe_decode(resp['registrationData']),
                         REG_DATA)
        self.assertEqual(sha256(APP_ID.encode()), app_param)

    def test_register_await_timeout(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = 'U2F_V2'
        client.ctap.authenticate.side_effect = ApduError(APDU.WRONG_DATA)
        client.ctap.register.side_effect = ApduError(APDU.USE_NOT_SATISFIED)

        client.poll_delay = 0.01
        try:
            client.register(
                APP_ID, [{'version': 'U2F_V2', 'challenge': 'foobar'}],
                [{'version': 'U2F_V2', 'keyHandle': 'a2V5'}],
                timeout=0.1
            )
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.TIMEOUT)

    def test_register_await_touch(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = 'U2F_V2'
        client.ctap.authenticate.side_effect = ApduError(APDU.WRONG_DATA)
        client.ctap.register.side_effect = [
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            REG_DATA
        ]

        event = Event()
        event.wait = mock.MagicMock()
        resp = client.register(
            APP_ID, [{'version': 'U2F_V2', 'challenge': 'foobar'}],
            [{'version': 'U2F_V2', 'keyHandle': 'a2V5'}],
            timeout=event
        )

        event.wait.assert_called()

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called_once()
        client.ctap.register.assert_called()

        client_param, app_param = client.ctap.register.call_args[0]
        self.assertEqual(sha256(websafe_decode(resp['clientData'])),
                         client_param)
        self.assertEqual(websafe_decode(resp['registrationData']),
                         REG_DATA)
        self.assertEqual(sha256(APP_ID.encode()), app_param)

    def test_sign_wrong_app_id(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = 'U2F_V2'

        try:
            client.sign(
                'http://foo.example.com', 'challenge',
                [{'version': 'U2F_V2', 'keyHandle': 'a2V5'}]
            )
            self.fail('sign did not raise error')
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.BAD_REQUEST)

    def test_sign_unsupported_version(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = 'U2F_XXX'

        try:
            client.sign(
                APP_ID, 'challenge',
                [{'version': 'U2F_V2', 'keyHandle': 'a2V5'}]
            )
            self.fail('sign did not raise error')
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.DEVICE_INELIGIBLE)

        client.ctap.get_version.assert_called_with()

    def test_sign_missing_key(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = 'U2F_V2'
        client.ctap.authenticate.side_effect = ApduError(APDU.WRONG_DATA)

        try:
            client.sign(
                APP_ID, 'challenge',
                [{'version': 'U2F_V2', 'keyHandle': 'a2V5'}],
            )
            self.fail('sign did not raise error')
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.DEVICE_INELIGIBLE)

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called_once()
        _, app_param, key_handle = client.ctap.authenticate.call_args[0]
        self.assertEqual(app_param, sha256(APP_ID.encode()))
        self.assertEqual(key_handle, b'key')

    def test_sign(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = 'U2F_V2'
        client.ctap.authenticate.return_value = SIG_DATA

        resp = client.sign(
            APP_ID, 'challenge',
            [{'version': 'U2F_V2', 'keyHandle': 'a2V5'}],
        )

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called_once()
        client_param, app_param, key_handle = \
            client.ctap.authenticate.call_args[0]

        self.assertEqual(client_param,
                         sha256(websafe_decode(resp['clientData'])))
        self.assertEqual(app_param, sha256(APP_ID.encode()))
        self.assertEqual(key_handle, b'key')
        self.assertEqual(websafe_decode(resp['signatureData']),
                         SIG_DATA)

    def test_sign_await_touch(self):
        client = U2fClient(None, APP_ID)
        client.ctap = mock.MagicMock()
        client.ctap.get_version.return_value = 'U2F_V2'
        client.ctap.authenticate.side_effect = [
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            ApduError(APDU.USE_NOT_SATISFIED),
            SIG_DATA
        ]

        event = Event()
        event.wait = mock.MagicMock()

        resp = client.sign(
            APP_ID, 'challenge',
            [{'version': 'U2F_V2', 'keyHandle': 'a2V5'}],
            timeout=event
        )

        event.wait.assert_called()

        client.ctap.get_version.assert_called_with()
        client.ctap.authenticate.assert_called()
        client_param, app_param, key_handle = \
            client.ctap.authenticate.call_args[0]

        self.assertEqual(client_param,
                         sha256(websafe_decode(resp['clientData'])))
        self.assertEqual(app_param, sha256(APP_ID.encode()))
        self.assertEqual(key_handle, b'key')
        self.assertEqual(websafe_decode(resp['signatureData']),
                         SIG_DATA)


class TestFido2Client(unittest.TestCase):
    pass
