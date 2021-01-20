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


from __future__ import absolute_import

import os
import uhid_freebsd

from .base import HidDescriptor, parse_report_descriptor, FileCtapHidConnection

import logging

logger = logging.getLogger(__name__)


def open_connection(descriptor):
    return FileCtapHidConnection(descriptor)


def _read_descriptor(vid, pid, path):
    fd = os.open(path, os.O_RDONLY)
    data = uhid_freebsd.get_report_data(fd, 3)
    os.close(fd)
    max_in_size, max_out_size = parse_report_descriptor(data)
    return HidDescriptor(path, vid, pid, max_in_size, max_out_size)


def get_descriptor(path):
    for dev in uhid_freebsd.enumerate():
        if dev["path"] == path:
            vid = dev["vendor_id"]
            pid = dev["product_id"]
            return _read_descriptor(vid, pid, path)
    raise ValueError("Device not found")


def list_descriptors():
    descriptors = []
    for dev in uhid_freebsd.enumerate():
        try:
            descriptors.append(
                _read_descriptor(dev["vendor_id"], dev["product_id"], dev["path"])
            )
            logger.debug("Found CTAP device: %s", dev["path"])
        except ValueError:
            pass  # Not a CTAP device, ignore
        except Exception as e:
            logger.debug("Failed opening HID device", exc_info=e)

    return descriptors
