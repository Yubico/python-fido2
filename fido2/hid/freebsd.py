# Original work Copyright 2016 Google Inc. All Rights Reserved.
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
#
# Modified work Copyright 2020 Yubico AB. All Rights Reserved.
# This file, with modifications, is licensed under the above Apache License.

from __future__ import annotations

from ctypes.util import find_library
import ctypes
import glob
import re
import os

from .base import HidDescriptor, parse_report_descriptor, FileCtapHidConnection

import logging
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)


devdir = "/dev/"

vendor_re = re.compile("vendor=(0x[0-9a-fA-F]+)")
product_re = re.compile("product=(0x[0-9a-fA-F]+)")
sernum_re = re.compile('sernum="([^"]+)')

libc = ctypes.CDLL(find_library("c"))

USB_GET_REPORT_DESC = 0xC0205515


class usb_gen_descriptor(ctypes.Structure):
    _fields_ = [
        (
            "ugd_data",
            ctypes.c_void_p,
        ),  # TODO: check what COMPAT_32BIT in C header means
        ("ugd_lang_id", ctypes.c_uint16),
        ("ugd_maxlen", ctypes.c_uint16),
        ("ugd_actlen", ctypes.c_uint16),
        ("ugd_offset", ctypes.c_uint16),
        ("ugd_config_index", ctypes.c_uint8),
        ("ugd_string_index", ctypes.c_uint8),
        ("ugd_iface_index", ctypes.c_uint8),
        ("ugd_altif_index", ctypes.c_uint8),
        ("ugd_endpt_index", ctypes.c_uint8),
        ("ugd_report_type", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 8),
    ]


def open_connection(descriptor):
    return FileCtapHidConnection(descriptor)


def _get_report_data(fd, report_type):
    data = ctypes.create_string_buffer(4096)
    desc = usb_gen_descriptor(
        ugd_data=ctypes.addressof(data),
        ugd_maxlen=ctypes.sizeof(data),
        report_type=report_type,
    )
    ret = libc.ioctl(fd, USB_GET_REPORT_DESC, ctypes.byref(desc))
    if ret != 0:
        raise ValueError("ioctl failed")
    return data.raw[: desc.ugd_actlen]


def _read_descriptor(vid, pid, name, serial, path):
    fd = os.open(path, os.O_RDONLY)
    data = _get_report_data(fd, 3)
    os.close(fd)
    max_in_size, max_out_size = parse_report_descriptor(data)
    return HidDescriptor(path, vid, pid, max_in_size, max_out_size, name, serial)


def _enumerate():
    for uhid in glob.glob(devdir + "uhid?*"):

        index = uhid[len(devdir) + len("uhid") :]
        if not index.isdigit():
            continue

        pnpinfo = ("dev.uhid." + index + ".%pnpinfo").encode()
        desc = ("dev.uhid." + index + ".%desc").encode()

        ovalue = ctypes.create_string_buffer(1024)
        olen = ctypes.c_size_t(ctypes.sizeof(ovalue))
        key = ctypes.c_char_p(pnpinfo)
        retval = libc.sysctlbyname(key, ovalue, ctypes.byref(olen), None, None)
        if retval != 0:
            continue

        dev: Dict[str, Optional[str]] = {}
        dev["name"] = uhid[len(devdir) :]
        dev["path"] = uhid

        value = ovalue.value[: olen.value].decode()
        m = vendor_re.search(value)
        dev["vendor_id"] = m.group(1) if m else None

        m = product_re.search(value)
        dev["product_id"] = m.group(1) if m else None

        m = sernum_re.search(value)
        dev["serial_number"] = m.group(1) if m else None

        key = ctypes.c_char_p(desc)
        retval = libc.sysctlbyname(key, ovalue, ctypes.byref(olen), None, None)
        if retval == 0:
            dev["product_desc"] = ovalue.value[: olen.value].decode() or None

        yield dev


def get_descriptor(path):
    for dev in _enumerate():
        if dev["path"] == path:
            vid = dev["vendor_id"]
            pid = dev["product_id"]
            name = dev["product_desc"] or None
            serial = (dev["serial_number"] if "serial_number" in dev else None) or None
            return _read_descriptor(vid, pid, name, serial, path)
    raise ValueError("Device not found")


# Cache for continuously failing devices
_failed_cache: Set[str] = set()


def list_descriptors():
    stale = set(_failed_cache)
    descriptors = []
    for dev in _enumerate():
        path = dev["path"]
        stale.discard(path)
        try:
            name = dev["product_desc"] or None
            serial = (dev["serial_number"] if "serial_number" in dev else None) or None
            descriptors.append(
                _read_descriptor(
                    dev["vendor_id"],
                    dev["product_id"],
                    name,
                    serial,
                    path,
                )
            )
        except ValueError:
            pass  # Not a CTAP device, ignore
        except Exception:
            if path not in _failed_cache:
                logger.debug("Failed opening HID device %s", path, exc_info=True)
                _failed_cache.add(path)

    return descriptors
