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

import struct
from unittest.mock import Mock, patch

import pytest

from fido2.hid import CtapHidDevice, open_device
from fido2.hid.base import parse_report_descriptor


def test_parse_report_descriptor_1():
    max_in_size, max_out_size = parse_report_descriptor(
        bytes.fromhex(
            "06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0"
        )
    )

    assert max_in_size == 64
    assert max_out_size == 64


def test_parse_report_descriptor_2():
    with pytest.raises(ValueError):
        parse_report_descriptor(
            bytes.fromhex(
                "05010902a1010901a10005091901290515002501950575018102950175038101"
                "05010930093109381581257f750895038106c0c0"
            )
        )


@pytest.mark.parametrize("enumerate_devices", [False, True])
@pytest.mark.parametrize("close_fails", [False, True])
@pytest.mark.parametrize(
    "error", [OSError("disconnected during INIT"), KeyboardInterrupt()]
)
def test_failed_open_closes_connection(enumerate_devices, close_fails, error):
    descriptor = Mock(report_size_out=64)
    connection = Mock()
    if close_fails:
        connection.close.side_effect = OSError("close failed")
    with (
        patch("fido2.hid.list_descriptors", return_value=[descriptor]),
        patch("fido2.hid.get_descriptor", return_value=descriptor),
        patch("fido2.hid.open_connection", return_value=connection),
        patch.object(CtapHidDevice, "call", side_effect=error),
        pytest.raises(type(error)) as raised,
    ):
        if enumerate_devices:
            next(CtapHidDevice.list_devices())
        else:
            open_device("fake-hid")
    assert raised.value is error
    connection.close.assert_called_once_with()


@pytest.mark.parametrize("enumerate_devices", [False, True])
def test_successful_open_transfers_connection_to_device(enumerate_devices):
    descriptor = Mock(report_size_out=64)
    connection = Mock()
    nonce = b"12345678"
    response = nonce + struct.pack(">IBBBBB", 1, 2, 3, 4, 5, 4)
    with (
        patch("fido2.hid.list_descriptors", return_value=[descriptor]),
        patch("fido2.hid.get_descriptor", return_value=descriptor),
        patch("fido2.hid.open_connection", return_value=connection),
        patch("fido2.hid.os.urandom", return_value=nonce),
        patch.object(CtapHidDevice, "call", return_value=response),
    ):
        if enumerate_devices:
            device = next(CtapHidDevice.list_devices())
        else:
            device = open_device("fake-hid")
    connection.close.assert_not_called()
    assert device.device_version == (3, 4, 5)
    device.close()
    connection.close.assert_called_once_with()
