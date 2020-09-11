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
"""Implements raw hid interface on OpenBSD with character devices"""

import fcntl
import select
import os
import os.path

from ctypes import (
    Structure,
    c_char,
    c_int,
    c_int32,
    c_uint8,
    c_uint16,
    c_uint32,
    c_void_p,
    c_long,
)

from . import base

# /usr/include/dev/usb/usb.h
USB_GET_DEVICEINFO = 0x421C5570
USB_MAX_STRING_LEN = 127
USB_MAX_DEVNAMES = 4
USB_MAX_DEVNAMELEN = 16

FIDO_DEVS = "/dev/fido"
MAX_U2F_HIDLEN = 64


class UsbDeviceInfo(Structure):
    _fields_ = [
        ("udi_bus", c_uint8),
        ("udi_addr", c_uint8),
        ("udi_product", c_char * USB_MAX_STRING_LEN),
        ("udi_vendor", c_char * USB_MAX_STRING_LEN),
        ("udi_release", c_char * 8),
        ("udi_productNo", c_uint16),
        ("udi_vendorNo", c_uint16),
        ("udi_releaseNo", c_uint16),
        ("udi_class", c_uint8),
        ("udi_subclass", c_uint8),
        ("udi_protocol", c_uint8),
        ("udi_config", c_uint8),
        ("udi_speed", c_uint8),
        ("udi_power", c_int),
        ("udi_nports", c_int),
        ("udi_devnames", c_char * USB_MAX_DEVNAMELEN * USB_MAX_DEVNAMES),
        ("udi_ports", c_uint8 * 8),
        ("udi_serial", c_char * USB_MAX_STRING_LEN),
    ]


def BaseDesc():
    desc = base.DeviceDescriptor()
    desc.internal_max_in_report_len = MAX_U2F_HIDLEN
    desc.internal_max_out_report_len = MAX_U2F_HIDLEN
    desc.usage = 0x1
    desc.usage_page = 0xF1D0
    return desc


class OpenBSDHidDevice(base.HidDevice):
    @staticmethod
    def Enumerate():
        for dev in os.listdir(FIDO_DEVS):
            path = os.path.join(FIDO_DEVS, dev)

            try:
                f = os.open(path, os.O_RDONLY)
            except OSError:
                continue

            dev_info = UsbDeviceInfo()
            desc = BaseDesc()
            desc.path = path

            try:
                fcntl.ioctl(f, USB_GET_DEVICEINFO, dev_info)
            except OSError:
                continue
            finally:
                os.close(f)

            desc.vendor_id = int(dev_info.udi_vendorNo)
            desc.vendor_string = dev_info.udi_vendor.decode("utf-8")
            desc.product_id = int(dev_info.udi_productNo)
            desc.product_string = dev_info.udi_product.decode("utf-8")

            yield desc.ToPublicDict()

    def __init__(self, path):
        base.HidDevice.__init__(self, path)
        self.desc = BaseDesc()
        self.desc.path = path
        self.dev = os.open(self.desc.path, os.O_RDWR)

        try:
            self.TerriblePingKludge()
        except:
            os.close(self.dev)
            raise

    def GetInReportDataLength(self):
        return self.desc.internal_max_in_report_len

    def GetOutReportDataLength(self):
        return self.desc.internal_max_out_report_len

    def Write(self, packet):
        out = bytes(bytearray(packet))
        os.write(self.dev, out)

    def Read(self):
        raw_in = os.read(self.dev, self.GetInReportDataLength())
        decoded_in = list(bytearray(raw_in))
        return decoded_in

    def TerriblePingKludge(self):
        """This is pulled from https://github.com/Yubico/libfido2/blob/da24193aa901086960f8d31b60d930ebef21f7a2/src/hid_openbsd.c#L128"""
        for _ in range(4):
            data = [0] * self.GetOutReportDataLength()
            data[0] = 0xFF
            data[1] = 0xFF
            data[2] = 0xFF
            data[3] = 0xFF
            # 1 byte ping
            data[4] = 0x81
            data[5] = 0
            data[6] = 1

            poll = select.poll()
            poll.register(self.dev, select.POLLIN)

            self.Write(data)

            poll.poll(100)
            data = self.Read()
