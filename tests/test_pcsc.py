# Copyright (c) 2019 Yubico AB
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

from unittest import mock

import pytest

from fido2.hid import CTAPHID


@pytest.fixture(autouse=True, scope="module")
def preconditions():
    global CtapPcscDevice
    try:
        from fido2.pcsc import CtapPcscDevice
    except ImportError:
        pytest.skip("pyscard is not installed")


def test_pcsc_call_cbor():
    connection = mock.Mock()
    connection.transmit.side_effect = [(b"U2F_V2", 0x90, 0x00), (b"", 0x90, 0x00)]

    CtapPcscDevice(connection, "Mock")

    connection.transmit.assert_called_with(
        [0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00], None
    )


def test_pcsc_call_u2f():
    connection = mock.Mock()
    connection.transmit.side_effect = [
        (b"U2F_V2", 0x90, 0x00),
        (b"", 0x90, 0x00),
        (b"u2f_resp", 0x90, 0x00),
    ]

    dev = CtapPcscDevice(connection, "Mock")
    res = dev.call(CTAPHID.MSG, b"\x00\x01\x00\x00\x05" + b"\x01" * 5 + b"\x00")

    connection.transmit.assert_called_with(
        [0x00, 0x01, 0x00, 0x00, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00], None
    )
    assert res == b"u2f_resp\x90\x00"


def test_pcsc_call_version_2():
    connection = mock.Mock()
    connection.transmit.side_effect = [(b"U2F_V2", 0x90, 0x00), (b"", 0x90, 0x00)]

    dev = CtapPcscDevice(connection, "Mock")

    assert dev.version == 2


def test_pcsc_call_version_1():
    connection = mock.Mock()
    connection.transmit.side_effect = [(b"U2F_V2", 0x90, 0x00), (b"", 0x63, 0x85)]

    dev = CtapPcscDevice(connection, "Mock")

    assert dev.version == 1
