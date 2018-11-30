from __future__ import absolute_import, unicode_literals

import unittest

from fido2.server import Fido2Server, RelyingParty


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
