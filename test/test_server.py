from __future__ import absolute_import, unicode_literals

import json
import unittest
from binascii import a2b_hex
import six

from fido2.client import WEBAUTHN_TYPE, ClientData
from fido2.ctap2 import AttestedCredentialData, AuthenticatorData
from fido2.server import USER_VERIFICATION, Fido2Server, RelyingParty

from .test_ctap2 import _ATT_CRED_DATA, _CRED_ID


class TestRelyingParty(unittest.TestCase):

    def test_id_hash(self):
        rp = RelyingParty('example.com')
        rp_id_hash = (b'\xa3y\xa6\xf6\xee\xaf\xb9\xa5^7\x8c\x11\x804\xe2u\x1eh/'
                      b'\xab\x9f-0\xab\x13\xd2\x12U\x86\xce\x19G')
        self.assertEqual(rp.id_hash, rp_id_hash)


class TestFido2Server(unittest.TestCase):

    def test_register_begin_rp_no_icon(self):
        rp = RelyingParty('example.com', 'Example')
        server = Fido2Server(rp)

        request, state = server.register_begin({})

        self.assertEqual(request['publicKey']['rp'],
                         {'id': 'example.com', 'name': 'Example'})

    def test_register_begin_rp_icon(self):
        rp = RelyingParty('example.com', 'Example',
                          'http://example.com/icon.svg')
        server = Fido2Server(rp)

        request, state = server.register_begin({})

        data = {'id': 'example.com', 'name': 'Example',
                'icon': 'http://example.com/icon.svg'}
        self.assertEqual(request['publicKey']['rp'], data)

    def test_authenticate_complete_invalid_signature(self):
        rp = RelyingParty('example.com', 'Example')
        server = Fido2Server(rp)

        state = {'challenge': 'GAZPACHO!',
                 'user_verification': USER_VERIFICATION.PREFERRED}
        client_data_dict = {'challenge': 'GAZPACHO!',
                            'origin': 'https://example.com',
                            'type': WEBAUTHN_TYPE.GET_ASSERTION}
        client_data = ClientData(json.dumps(client_data_dict).encode('utf-8'))
        _AUTH_DATA = a2b_hex('A379A6F6EEAFB9A55E378C118034E2751E682FAB9F2D30AB13D2125586CE1947010000001D')  # noqa
        with six.assertRaisesRegex(self, ValueError, 'Invalid signature.'):
            server.authenticate_complete(
                state, [AttestedCredentialData(_ATT_CRED_DATA)], _CRED_ID,
                client_data, AuthenticatorData(_AUTH_DATA), b'INVALID')
