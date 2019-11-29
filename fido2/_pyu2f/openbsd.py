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

import ctypes
import ctypes.util
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

# /usr/include/dev/hid/hid.h
hid_input = 0
hid_output = 1

# /usr/include/dev/usb/usb.h
USB_GET_DEVICEINFO = 0x421C5570
USB_GET_REPORT_ID = 0x40045519
USB_MAX_STRING_LEN = 127
USB_MAX_DEVNAMES = 4
USB_MAX_DEVNAMELEN = 16


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


class HidItem(Structure):
    _fields_ = [
        ("_usage_page", c_uint32),
        ("logical_minimum", c_int32),
        ("logical_maximum", c_int32),
        ("physical_minimum", c_int32),
        ("physical_maximum", c_int32),
        ("unit_exponent", c_int32),
        ("unit", c_int32),
        ("report_size", c_int32),
        ("report_ID", c_int32),
        ("report_count", c_int32),
        ("usage", c_uint32),
        ("usage_minimum", c_int32),
        ("usage_maximum", c_int32),
        ("designator_index", c_int32),
        ("designator_minimum", c_int32),
        ("designator_maximum", c_int32),
        ("string_index", c_int32),
        ("string_minimum", c_int32),
        ("string_maximum", c_int32),
        ("set_delimiter", c_int32),
        ("collection", c_int32),
        ("collevel", c_int),
        ("kind", c_int),
        ("flags", c_uint32),
        ("pos", c_uint32),
        ("next", c_void_p),
    ]


def GetLibUsbHid():
    libusbhid = ctypes.CDLL(ctypes.util.find_library("usbhid"))
    libusbhid.hid_get_report_desc.restype = c_void_p
    libusbhid.hid_start_parse.restype = c_void_p
    return libusbhid


def ReadReportDescriptor(device_fd, desc):
    libusbhid = GetLibUsbHid()
    usb_report_id = c_int(0)

    fcntl.ioctl(device_fd, USB_GET_REPORT_ID, ctypes.pointer(usb_report_id))

    rdesc = libusbhid.hid_get_report_desc(device_fd)
    if rdesc == None:
        raise OSError("Cannot get report descriptor")

    try:
        hiddata = libusbhid.hid_start_parse(c_void_p(rdesc), 1 << 3, 0)
        if hiddata == None:
            raise OSError("Cannot get hiddata")

        desc.internal_max_in_report_len = libusbhid.hid_report_size(
            c_void_p(rdesc), hid_input, usb_report_id
        )
        desc.internal_max_out_report_len = libusbhid.hid_report_size(
            c_void_p(rdesc), hid_output, usb_report_id
        )

        hiditem = HidItem()
        res = libusbhid.hid_get_item(c_void_p(hiddata), ctypes.byref(hiditem))
        if res < 0:
            raise OSError("Cannot get hiddata")
        desc.usage_page = (hiditem.usage & 0xFFFF0000) >> 16
        desc.usage = hiditem.usage & 0x0000FFFF
    finally:
        libusbhid.hid_dispose_report_desc(c_void_p(rdesc))


class OpenBSDHidDevice(base.HidDevice):
    @staticmethod
    def Enumerate():
        for dev in os.listdir("/dev/"):
            if not dev.startswith("uhid"):
                continue

            path = os.path.join("/dev", dev)

            try:
                f = os.open(path, os.O_RDONLY)
            except OSError:
                continue

            dev_info = UsbDeviceInfo()
            desc = base.DeviceDescriptor()
            desc.path = path

            try:
                fcntl.ioctl(f, USB_GET_DEVICEINFO, dev_info)

                desc.vendor_id = int(dev_info.udi_vendorNo)
                desc.vendor_string = dev_info.udi_vendor.decode("utf-8")
                desc.product_id = int(dev_info.udi_productNo)
                desc.product_string = dev_info.udi_product.decode("utf-8")
                ReadReportDescriptor(f, desc)
                os.close(f)
            except OSError:
                continue

            yield desc.ToPublicDict()

    def __init__(self, path):
        base.HidDevice.__init__(self, path)
        self.desc = base.DeviceDescriptor()
        self.desc.path = path
        self.dev = os.open(self.desc.path, os.O_RDWR)
        ReadReportDescriptor(self.dev, self.desc)

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
