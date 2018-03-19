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

from fido_host.fido2 import (CTAP2, PinProtocolV1, Info, AttestedCredentialData,
                             AuthenticatorData, AttestationObject,
                             AssertionResponse)
from fido_host import cbor
from binascii import a2b_hex
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

import unittest
import mock

_AAGUID = a2b_hex('F8A011F38C0A4D15800617111F9EDC7D')
_INFO = a2b_hex('a60182665532465f5632684649444f5f325f3002826375766d6b686d61632d7365637265740350f8a011f38c0a4d15800617111f9edc7d04a462726bf5627570f564706c6174f469636c69656e7450696ef4051904b0068101')  # noqa


class TestInfo(unittest.TestCase):
    def test_parse_bytes(self):
        info = Info(_INFO)

        self.assertEqual(info.versions, ['U2F_V2', 'FIDO_2_0'])
        self.assertEqual(info.extensions, ['uvm', 'hmac-secret'])
        self.assertEqual(info.aaguid, _AAGUID)
        self.assertEqual(info.options, {
            'rk': True,
            'up': True,
            'plat': False,
            'clientPin': False
        })
        self.assertEqual(info.max_msg_size, 1200)
        self.assertEqual(info.pin_protocols, [1])
        self.assertEqual(info.data, {
            Info.KEY.VERSIONS: ['U2F_V2', 'FIDO_2_0'],
            Info.KEY.EXTENSIONS: ['uvm', 'hmac-secret'],
            Info.KEY.AAGUID: _AAGUID,
            Info.KEY.OPTIONS: {
                'clientPin': False,
                'plat': False,
                'rk': True,
                'up': True
            },
            Info.KEY.MAX_MSG_SIZE: 1200,
            Info.KEY.PIN_PROTOCOLS: [1]
        })


_ATT_CRED_DATA = a2b_hex('f8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290')  # noqa
_CRED_ID = a2b_hex('fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783')  # noqa
_PUB_KEY = {1: 2, 3: -7, -1: 1, -2: a2b_hex('643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf'), -3: a2b_hex('171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290')}  # noqa


class TestAttestedCredentialData(unittest.TestCase):
    def test_parse_bytes(self):
        data = AttestedCredentialData(_ATT_CRED_DATA)
        self.assertEqual(data.aaguid, _AAGUID)
        self.assertEqual(data.credential_id, _CRED_ID)
        self.assertEqual(data.public_key, _PUB_KEY)

    def test_create_from_args(self):
        data = AttestedCredentialData.create(_AAGUID, _CRED_ID, _PUB_KEY)
        self.assertEqual(_ATT_CRED_DATA, data)


_AUTH_DATA_MC = a2b_hex('0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12410000001CF8A011F38C0A4D15800617111F9EDC7D0040FE3AAC036D14C1E1C65518B698DD1DA8F596BC33E11072813466C6BF3845691509B80FB76D59309B8D39E0A93452688F6CA3A39A76F3FC52744FB73948B15783A5010203262001215820643566C206DD00227005FA5DE69320616CA268043A38F08BDE2E9DC45A5CAFAF225820171353B2932434703726AAE579FA6542432861FE591E481EA22D63997E1A5290')  # noqa
_AUTH_DATA_GA = a2b_hex('0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000001D')  # noqa
_RP_ID_HASH = a2b_hex('0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12')  # noqa


class TestAuthenticatorData(unittest.TestCase):
    def test_parse_bytes_make_credential(self):
        data = AuthenticatorData(_AUTH_DATA_MC)
        self.assertEqual(data.rp_id_hash, _RP_ID_HASH)
        self.assertEqual(data.flags, 0x41)
        self.assertEqual(data.counter, 28)
        self.assertEqual(data.credential_data, _ATT_CRED_DATA)
        self.assertIsNone(data.extensions)

    def test_parse_bytes_get_assertion(self):
        data = AuthenticatorData(_AUTH_DATA_GA)
        self.assertEqual(data.rp_id_hash, _RP_ID_HASH)
        self.assertEqual(data.flags, 0x01)
        self.assertEqual(data.counter, 29)
        self.assertIsNone(data.credential_data)
        self.assertIsNone(data.extensions)


_MC_RESP = a2b_hex('a301667061636b6564025900c40021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12410000001cf8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a529003a363616c67266373696758483046022100cc1ef43edf07de8f208c21619c78a565ddcf4150766ad58781193be8e0a742ed022100f1ed7c7243e45b7d8e5bda6b1abf10af7391789d1ef21b70bd69fed48dba4cb163783563815901973082019330820138a003020102020900859b726cb24b4c29300a06082a8648ce3d0403023047310b300906035504061302555331143012060355040a0c0b59756269636f205465737431223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e301e170d3136313230343131353530305a170d3236313230323131353530305a3047310b300906035504061302555331143012060355040a0c0b59756269636f205465737431223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3059301306072a8648ce3d020106082a8648ce3d03010703420004ad11eb0e8852e53ad5dfed86b41e6134a18ec4e1af8f221a3c7d6e636c80ea13c3d504ff2e76211bb44525b196c44cb4849979cf6f896ecd2bb860de1bf4376ba30d300b30090603551d1304023000300a06082a8648ce3d0403020349003046022100e9a39f1b03197525f7373e10ce77e78021731b94d0c03f3fda1fd22db3d030e7022100c4faec3445a820cf43129cdb00aabefd9ae2d874f9c5d343cb2f113da23723f3')  # noqa
_GA_RESP = a2b_hex('a301a26269645840fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b1578364747970656a7075626c69632d6b6579025900250021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12010000001d035846304402206765cbf6e871d3af7f01ae96f06b13c90f26f54b905c5166a2c791274fc2397102200b143893586cc799fba4da83b119eaea1bd80ac3ce88fcedb3efbd596a1f4f63')  # noqa
_CRED_ID = a2b_hex('FE3AAC036D14C1E1C65518B698DD1DA8F596BC33E11072813466C6BF3845691509B80FB76D59309B8D39E0A93452688F6CA3A39A76F3FC52744FB73948B15783')  # noqa
_CRED = {'type': 'public-key', 'id': _CRED_ID}
_SIGNATURE = a2b_hex('304402206765CBF6E871D3AF7F01AE96F06B13C90F26F54B905C5166A2C791274FC2397102200B143893586CC799FBA4DA83B119EAEA1BD80AC3CE88FCEDB3EFBD596A1F4F63')  # noqa


class TestCTAP2(unittest.TestCase):
    def test_send_cbor_ok(self):
        ctap = CTAP2(mock.MagicMock())
        ctap.device.call.return_value = b'\0' + cbor.dumps({1: b'response'})

        self.assertEqual({1: b'response'}, ctap.send_cbor(2, b'foobar'))
        ctap.device.call.assert_called_with(0x10, b'\2' + cbor.dumps(b'foobar'),
                                            None)

    def test_get_info(self):
        ctap = CTAP2(mock.MagicMock())
        ctap.device.call.return_value = b'\0' + _INFO

        info = ctap.get_info()
        ctap.device.call.assert_called_with(0x10, b'\4', None)
        self.assertIsInstance(info, Info)

    def test_make_credential(self):
        ctap = CTAP2(mock.MagicMock())
        ctap.device.call.return_value = b'\0' + _MC_RESP

        resp = ctap.make_credential(1, 2, 3, 4)
        ctap.device.call.assert_called_with(
            0x10, b'\1' + cbor.dumps({1: 1, 2: 2, 3: 3, 4: 4}), None)

        self.assertIsInstance(resp, AttestationObject)
        self.assertEqual(resp, _MC_RESP)
        self.assertEqual(resp.fmt, 'packed')
        self.assertEqual(resp.auth_data, _AUTH_DATA_MC)
        self.assertSetEqual(set(resp.att_statement.keys()),
                            {'alg', 'sig', 'x5c'})

    def test_get_assertion(self):
        ctap = CTAP2(mock.MagicMock())
        ctap.device.call.return_value = b'\0' + _GA_RESP

        resp = ctap.get_assertion(1, 2)
        ctap.device.call.assert_called_with(
            0x10, b'\2' + cbor.dumps({1: 1, 2: 2}), None)

        self.assertIsInstance(resp, AssertionResponse)
        self.assertEqual(resp, _GA_RESP)
        self.assertEqual(resp.credential, _CRED)
        self.assertEqual(resp.auth_data, _AUTH_DATA_GA)
        self.assertEqual(resp.signature, _SIGNATURE)
        self.assertIsNone(resp.user)
        self.assertIsNone(resp.number_of_credentials)


EC_PRIV = 0x7452e599fee739d8a653f6a507343d12d382249108a651402520b72f24fe7684
EC_PUB_X = a2b_hex('44D78D7989B97E62EA993496C9EF6E8FD58B8B00715F9A89153DDD9C4657E47F')  # noqa
EC_PUB_Y = a2b_hex('EC802EE7D22BD4E100F12E48537EB4E7E96ED3A47A0A3BD5F5EEAB65001664F9')  # noqa
DEV_PUB_X = a2b_hex('0501D5BC78DA9252560A26CB08FCC60CBE0B6D3B8E1D1FCEE514FAC0AF675168')  # noqa
DEV_PUB_Y = a2b_hex('D551B3ED46F665731F95B4532939C25D91DB7EB844BD96D4ABD4083785F8DF47')  # noqa
SHARED = a2b_hex('c42a039d548100dfba521e487debcbbb8b66bb7496f8b1862a7a395ed83e1a1c')  # noqa
TOKEN_ENC = a2b_hex('7A9F98E31B77BE90F9C64D12E9635040')
TOKEN = a2b_hex('aff12c6dcfbf9df52f7a09211e8865cd')
PIN_HASH_ENC = a2b_hex('afe8327ce416da8ee3d057589c2ce1a9')


class TestPinProtocolV1(unittest.TestCase):

    @mock.patch('cryptography.hazmat.primitives.asymmetric.ec.generate_private_key')  # noqa
    def test_establish_shared_secret(self, patched_generate):
        prot = PinProtocolV1(mock.MagicMock())

        patched_generate.return_value = ec.derive_private_key(
            EC_PRIV,
            ec.SECP256R1(),
            default_backend()
        )

        prot.ctap.client_pin.return_value = {
            1: {
                1: 2,
                3: -25,
                -1: 1,
                -2: DEV_PUB_X,
                -3: DEV_PUB_Y
            }
        }

        key_agreement, shared = prot._init_shared_secret()

        self.assertEqual(shared, SHARED)
        self.assertEqual(key_agreement[-2], EC_PUB_X)
        self.assertEqual(key_agreement[-3], EC_PUB_Y)

    def test_get_pin_token(self):
        prot = PinProtocolV1(mock.MagicMock())
        prot._init_shared_secret = mock.Mock(return_value=({}, SHARED))
        prot.ctap.client_pin.return_value = {
            2: TOKEN_ENC
        }

        self.assertEqual(prot.get_pin_token('1234'), TOKEN)
        prot.ctap.client_pin.assert_called_once()
        self.assertEqual(prot.ctap.client_pin.call_args[1]['pin_hash_enc'],
                         PIN_HASH_ENC)

    def test_set_pin(self):
        prot = PinProtocolV1(mock.MagicMock())
        prot._init_shared_secret = mock.Mock(return_value=({}, SHARED))

        prot.set_pin('1234')
        prot.ctap.client_pin.assert_called_with(
            1,
            3,
            key_agreement={},
            new_pin_enc=a2b_hex('0222fc42c6dd76a274a7057858b9b29d98e8a722ec2dc6668476168c5320473cec9907b4cd76ce7943c96ba5683943211d84471e64d9c51e54763488cd66526a'),  # noqa
            pin_auth=a2b_hex('7b40c084ccc5794194189ab57836475f')
        )

    def test_change_pin(self):
        prot = PinProtocolV1(mock.MagicMock())
        prot._init_shared_secret = mock.Mock(return_value=({}, SHARED))

        prot.change_pin('1234', '4321')
        prot.ctap.client_pin.assert_called_with(
            1,
            4,
            key_agreement={},
            new_pin_enc=a2b_hex('4280e14aac4fcbf02dd079985f0c0ffc9ea7d5f9c173fd1a4c843826f7590cb3c2d080c6923e2fe6d7a52c31ea1309d3fcca3dedae8a2ef14b6330cafc79339e'),  # noqa
            pin_auth=a2b_hex('fb97e92f3724d7c85e001d7f93e6490a'),
            pin_hash_enc=a2b_hex('afe8327ce416da8ee3d057589c2ce1a9')
        )

    def test_short_pin(self):
        prot = PinProtocolV1(mock.MagicMock())
        with self.assertRaises(ValueError):
            prot.set_pin('123')

    def test_long_pin(self):
        prot = PinProtocolV1(mock.MagicMock())
        with self.assertRaises(ValueError):
            prot.set_pin('1'*256)
