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

import unittest

from fido2.hid import CtapHidDevice
from fido2.hid.base import parse_report_descriptor


class HidTest(unittest.TestCase):
    def get_device(self):
        try:
            devs = list(CtapHidDevice.list_devices())
            assert len(devs) == 1
            return devs[0]
        except Exception:
            self.skipTest("Tests require a single FIDO HID device")

    def test_ping(self):
        msg1 = b"hello world!"
        msg2 = b"            "
        msg3 = b""
        dev = self.get_device()
        self.assertEqual(dev.ping(msg1), msg1)
        self.assertEqual(dev.ping(msg2), msg2)
        self.assertEqual(dev.ping(msg3), msg3)


class TestReportDescriptor(unittest.TestCase):
    def test_parse_report_descriptor_1(self):
        max_in_size, max_out_size = parse_report_descriptor(
            bytes.fromhex(
                "06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0"
            )
        )

        self.assertEqual(max_in_size, 64)
        self.assertEqual(max_out_size, 64)

    def test_parse_report_descriptor_2(self):
        with self.assertRaises(ValueError):
            parse_report_descriptor(
                bytes.fromhex(
                    "05010902a1010901a10005091901290515002501950575018102950175038101"
                    "05010930093109381581257f750895038106c0c0"
                )
            )
