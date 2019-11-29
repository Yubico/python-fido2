# Copyright 2019 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for OpenBSD hid interface"""

import ctypes
import os.path
import sys

import mock

from fido2._pyu2f.base import DeviceDescriptor

if sys.platform.startswith("openbsd"):
    from fido2._pyu2f import openbsd

if sys.version_info[:2] < (2, 7):
    import unittest2 as unittest  # pylint: disable=g-import-not-at-top
else:
    import unittest  # pylint: disable=g-import-not-at-top


class FakeOsModule:
    data = None
    dirs = None
    path = os.path
    O_RDONLY = 0
    O_RDWR = 0

    def open(self, path, opts):
        return 0

    def write(self, fd, data):
        self.data = data

    def read(self, fd, len_):
        return self.data

    def close(self, fd):
        pass

    def listdir(self, dir_):
        return self.dirs


class FakeLibUsbHid:
    hiddata = None
    rdesc = None
    hiditem_ret = 0
    hiditem = None

    def hid_get_report_desc(self, fd):
        return self.rdesc

    def hid_start_parse(self, rdesc, kindset, id_):
        return self.hiddata

    def hid_report_size(self, rdesc, endpoint, report_id):
        return 64

    def hid_get_item(self, hiddata, hiditem):
        if self.hiditem is not None:
            for (fld, _) in self.hiditem._fields_:
                setattr(hiditem, fld, getattr(self.hiditem, fld, 0))
        return self.hiditem_ret

    def hid_dispose_report_desc(self, rdesc):
        pass


@unittest.skipIf(not sys.platform.startswith("openbsd"), "OpenBSD specific test cases")
class OpenBSDTest(unittest.TestCase):
    def testReadReportDescriptorNoDesc(self):
        fake_libusbhid = FakeLibUsbHid()

        with mock.patch(
            "fido2._pyu2f.openbsd.GetLibUsbHid", return_value=fake_libusbhid
        ), mock.patch("fido2._pyu2f.openbsd.fcntl"):
            with self.assertRaises(OSError):
                openbsd.ReadReportDescriptor(0, {})

    def testReadReportDescriptorBadHidData(self):
        fake_libusbhid = FakeLibUsbHid()
        fake_libusbhid.rdesc = 0
        fake_libusbhid.hiddata = None

        with mock.patch(
            "fido2._pyu2f.openbsd.GetLibUsbHid", return_value=fake_libusbhid
        ), mock.patch("fido2._pyu2f.openbsd.fcntl"):
            with self.assertRaises(OSError):
                openbsd.ReadReportDescriptor(0, {})

    def testReadReportDescriptorBadHidItem(self):
        fake_libusbhid = FakeLibUsbHid()
        fake_libusbhid.rdesc = 0
        fake_libusbhid.hiddata = 0
        fake_libusbhid.hiditem_ret = -1

        def test_byref(val):
            return val

        with mock.patch(
            "fido2._pyu2f.openbsd.GetLibUsbHid", return_value=fake_libusbhid
        ), mock.patch("fido2._pyu2f.openbsd.fcntl"), mock.patch(
            "fido2._pyu2f.openbsd.ctypes.byref", test_byref
        ):
            with self.assertRaises(OSError):
                openbsd.ReadReportDescriptor(0, DeviceDescriptor())

    def testReadReportDescriptor(self):
        fake_libusbhid = FakeLibUsbHid()
        fake_libusbhid.rdesc = 0
        fake_libusbhid.hiddata = 0
        fake_libusbhid.hiditem_ret = 1

        fake_libusbhid.hiditem = openbsd.HidItem(usage=0x00020001)

        def test_byref(val):
            return val

        with mock.patch(
            "fido2._pyu2f.openbsd.GetLibUsbHid", return_value=fake_libusbhid
        ), mock.patch("fido2._pyu2f.openbsd.fcntl"), mock.patch(
            "fido2._pyu2f.openbsd.ctypes.byref", test_byref
        ):
            desc = DeviceDescriptor()
            openbsd.ReadReportDescriptor(0, desc)

            self.assertEqual(desc.usage_page, 2)
            self.assertEqual(desc.usage, 1)

    def testInvalidEnumerate(self):
        fake_os = FakeOsModule()
        fake_libusbhid = FakeLibUsbHid()

        def usb_get_device(fd, _, dev_info):
            dev_info.udi_vendorNo = ctypes.c_uint16(0x1050)
            dev_info.udi_vendor = b"Yubico"
            dev_info.udi_productNo = ctypes.c_uint16(0x0407)
            dev_info.udi_product = b"YubiKey OTP+FIDO+CCID"

        fake_os.dirs = ["uhid20", "sd0a"]

        with mock.patch("fido2._pyu2f.openbsd.os", fake_os), mock.patch(
            "fido2._pyu2f.openbsd.fcntl.ioctl", side_effect=usb_get_device
        ), mock.patch(
            "fido2._pyu2f.openbsd.GetLibUsbHid", return_value=fake_libusbhid
        ), mock.patch(
            "fido2._pyu2f.openbsd.ReadReportDescriptor", side_effect=OSError
        ):
            devs = list(openbsd.OpenBSDHidDevice.Enumerate())
            self.assertEqual(len(devs), 0)

    def testEnumerate(self):
        fake_os = FakeOsModule()
        fake_libusbhid = FakeLibUsbHid()

        def usb_get_device(fd, _, dev_info):
            dev_info.udi_vendorNo = ctypes.c_uint16(0x1050)
            dev_info.udi_vendor = b"Yubico"
            dev_info.udi_productNo = ctypes.c_uint16(0x0407)
            dev_info.udi_product = b"YubiKey OTP+FIDO+CCID"

        fake_os.dirs = ["uhid20", "sd0a"]

        with mock.patch("fido2._pyu2f.openbsd.os", fake_os), mock.patch(
            "fido2._pyu2f.openbsd.fcntl.ioctl", side_effect=usb_get_device
        ), mock.patch(
            "fido2._pyu2f.openbsd.GetLibUsbHid", return_value=fake_libusbhid
        ), mock.patch(
            "fido2._pyu2f.openbsd.ReadReportDescriptor"
        ):
            devs = list(openbsd.OpenBSDHidDevice.Enumerate())
            self.assertEqual(len(devs), 1)
            dev = devs[0]
            self.assertEqual(dev["vendor_id"], 0x1050)
            self.assertEqual(dev["product_id"], 0x0407)
            self.assertEqual(dev["vendor_string"], "Yubico")
            self.assertEqual(dev["product_string"], "YubiKey OTP+FIDO+CCID")


if __name__ == "__main__":
    unittest.main()
