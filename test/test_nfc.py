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

from fido2.nfc import CtapNfcDevice
from fido2.hid import CTAPHID
import unittest
import mock


class NfcTest(unittest.TestCase):
    def test_nfc_call_ping(self):
        dev = mock.Mock()

        nfc_dev = CtapNfcDevice(None, dev, no_card=True)
        res = nfc_dev.call(CTAPHID.PING, b'12345')

        dev.apdu_exchange.assert_not_called()
        assert res == b'12345'

    def test_nfc_call_cbor(self):
        dev = mock.Mock()
        dev.apdu_exchange.return_value = (b'version', 0x90, 0x00)

        nfc_dev = CtapNfcDevice(None, dev, no_card=True)
        res = nfc_dev.call(CTAPHID.CBOR, b'\x04')

        dev.apdu_exchange.assert_called_once_with(b'\x80\x10\x00\x00\x01\x04\x00')
        assert res == b'version'

    def test_nfc_call_u2f(self):
        dev = mock.Mock()
        dev.apdu_exchange.return_value = (b'version', 0x90, 0x00)

        nfc_dev = CtapNfcDevice(None, dev, no_card=True)
        res = nfc_dev.call(CTAPHID.MSG, b'\x00\x01\x00\x00\x00\x00\x05' + b'\x01' * 5 + b'\x00\x00')

        dev.apdu_exchange.assert_called_once_with(b'\x00\x01\x03\x00\x05\x01\x01\x01\x01\x01\x00')
        assert res == b'version\x90\x00'

    def test_nfc_call_version_2(self):
        dev = mock.Mock()
        dev.apdu_exchange.return_value = (b'version', 0x90, 0x00)

        nfc_dev = CtapNfcDevice(None, dev, no_card=True)
        res = nfc_dev.version

        dev.apdu_exchange.assert_called_once_with(b'\x80\x10\x00\x00\x01\x04\x00')
        assert res == 2

    def test_nfc_call_version_1(self):
        dev = mock.Mock()
        dev.apdu_exchange.return_value = (b'', 0x63, 0x85)

        nfc_dev = CtapNfcDevice(None, dev, no_card=True)
        res = nfc_dev.version

        dev.apdu_exchange.assert_called_once_with(b'\x80\x10\x00\x00\x01\x04\x00')
        assert res == 1
