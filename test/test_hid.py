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

from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice
import unittest
import mock


class HidTest(unittest.TestCase):
    def get_device(self):
        try:
            devs = list(CtapHidDevice.list_devices())
            assert len(devs) == 1
            return devs[0]
        except Exception:
            self.skipTest('Tests require a single FIDO HID device')

    def test_ping(self):
        msg1 = b'hello world!'
        msg2 = b'            '
        msg3 = b''
        dev = self.get_device()
        self.assertEqual(dev.ping(msg1), msg1)
        self.assertEqual(dev.ping(msg2), msg2)
        self.assertEqual(dev.ping(msg3), msg3)

    def test_call_error(self):
        dev = mock.Mock()
        hid_dev = CtapHidDevice(None, dev)
        dev.InternalRecv = mock.Mock(return_value=(0xbf, bytearray([7])))
        try:
            hid_dev.call(0x01)
            self.fail('call did not raise exception')
        except CtapError as e:
            self.assertEqual(e.code, 7)

    def test_call_keepalive(self):
        dev = mock.Mock()
        hid_dev = CtapHidDevice(None, dev)
        on_keepalive = mock.MagicMock()

        dev.InternalRecv = mock.Mock(side_effect=[
            (0xbb, bytearray([0])),
            (0xbb, bytearray([0])),
            (0xbb, bytearray([0])),
            (0xbb, bytearray([0])),
            (0x81, bytearray(b'done'))
        ])

        self.assertEqual(hid_dev.call(0x01, on_keepalive=on_keepalive), b'done')
        on_keepalive.assert_called_once_with(0)

        dev.InternalRecv.side_effect = [
            (0xbb, bytearray([1])),
            (0xbb, bytearray([0])),
            (0xbb, bytearray([0])),
            (0xbb, bytearray([1])),
            (0xbb, bytearray([1])),
            (0xbb, bytearray([1])),
            (0xbb, bytearray([1])),
            (0xbb, bytearray([0])),
            (0x81, bytearray(b'done'))
        ]
        on_keepalive.reset_mock()
        self.assertEqual(hid_dev.call(0x01, on_keepalive=on_keepalive), b'done')
        self.assertEqual(
            on_keepalive.call_args_list,
            [mock.call(1), mock.call(0), mock.call(1), mock.call(0)]
        )
