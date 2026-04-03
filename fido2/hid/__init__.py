# Copyright (c) 2020 Yubico AB
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

from __future__ import annotations

import logging
import struct
from enum import IntEnum, IntFlag, unique
from threading import Event
from typing import Callable, Iterator

from _fido2_native import hid as _hid  # type: ignore[reportAttributeAccessIssue]

from ..ctap import STATUS, CtapDevice
from ..ctap import CtapError as CtapError

logger = logging.getLogger(__name__)


def list_descriptors():
    return _hid.list_descriptors()


class ConnectionFailure(Exception):
    """The CTAP connection failed or returned an invalid response."""


@unique
class CTAPHID(IntEnum):
    PING = 0x01
    MSG = 0x03
    LOCK = 0x04
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11

    ERROR = 0x3F
    KEEPALIVE = 0x3B

    VENDOR_FIRST = 0x40


@unique
class CAPABILITY(IntFlag):
    WINK = 0x01
    LOCK = 0x02  # Not used
    CBOR = 0x04
    NMSG = 0x08

    def supported(self, flags: CAPABILITY) -> bool:
        return bool(flags & self)


TYPE_INIT = 0x80


class CtapHidDevice(CtapDevice):
    """
    CtapDevice implementation using the HID transport (native Rust backend).

    :cvar descriptor: Device descriptor.
    """

    def __init__(self, descriptor: _hid.HidDescriptor):
        self.descriptor = descriptor
        self._connection = _hid.CtapHidConnection(descriptor)
        self._capabilities = self._connection.capabilities
        self._device_version = self._connection.device_version

    def __repr__(self):
        return f"CtapHidDevice({self.descriptor.path!r})"

    @property
    def version(self) -> int:
        """CTAP HID protocol version."""
        return 2  # We only support CTAP HID v2

    @property
    def device_version(self) -> tuple[int, int, int]:
        """Device version number."""
        return self._device_version

    @property
    def capabilities(self) -> int:
        """Capabilities supported by the device."""
        return self._capabilities

    @property
    def product_name(self) -> str | None:
        """Product name of device."""
        return self.descriptor.product_name

    @property
    def serial_number(self) -> str | None:
        """Serial number of device."""
        return self.descriptor.serial_number

    def call(
        self,
        cmd: int,
        data: bytes = b"",
        event: Event | None = None,
        on_keepalive: Callable[[STATUS], None] | None = None,
    ) -> bytes:
        event = event or Event()

        _ka_cb: Callable[[int], None] | None = None
        if on_keepalive:
            last_ka: STATUS | None = None

            def _on_keepalive(status: int) -> None:
                nonlocal last_ka
                try:
                    ka_status = STATUS(status)
                except ValueError:
                    return
                if ka_status != last_ka:
                    last_ka = ka_status
                    on_keepalive(ka_status)

            _ka_cb = _on_keepalive

        while True:
            try:
                return self._connection.call(cmd, data, event, _ka_cb)
            except OSError as e:
                err_msg = str(e)
                if "ChannelBusy" in err_msg:
                    if not event.wait(0.1):
                        logger.warning("CTAP channel busy, trying again...")
                        continue
                raise

    def wink(self) -> None:
        """Causes the authenticator to blink."""
        self.call(CTAPHID.WINK)

    def ping(self, msg: bytes = b"Hello FIDO") -> bytes:
        """Sends data to the authenticator, which echoes it back.

        :param msg: The data to send.
        :return: The response from the authenticator.
        """
        return self.call(CTAPHID.PING, msg)

    def lock(self, lock_time: int = 10) -> None:
        """Locks the channel."""
        self.call(CTAPHID.LOCK, struct.pack(">B", lock_time))

    def close(self) -> None:
        self._connection.close()

    @classmethod
    def list_devices(cls) -> Iterator[CtapHidDevice]:
        for d in _hid.list_descriptors():
            try:
                yield cls(d)
            except Exception:
                logger.debug("Failed to open device %s", d.path, exc_info=True)


def list_devices() -> Iterator[CtapHidDevice]:
    return CtapHidDevice.list_devices()


def open_device(path) -> CtapHidDevice:
    for d in _hid.list_descriptors():
        if d.path == path:
            return CtapHidDevice(d)
    raise ValueError(f"Device not found: {path}")
