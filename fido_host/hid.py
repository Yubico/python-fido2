
from __future__ import absolute_import

from .ctap import CtapDevice
from .pyu2f import hidtransport

from enum import IntEnum, unique
from threading import Event
import struct


@unique
class CTAPHID(IntEnum):
    PING = 0x01
    MSG = 0x03
    LOCK = 0x04
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11

    ERROR = 0x3f
    KEEPALIVE = 0x3b

    VENDOR_FIRST = 0x40


@unique
class CAPABILITY(IntEnum):
    WINK = 0x01
    LOCK = 0x02  # Not used
    CBOR = 0x04
    NMSG = 0x08

    def supported(self, flags):
        return bool(flags & self)


TYPE_INIT = 0x80


class CtapError(Exception):
    @unique
    class ERR(IntEnum):
        SUCCESS = 0x00
        INVALID_COMMAND = 0x01
        INVALID_PARAMETER = 0x02
        INVALID_LENGTH = 0x03
        INVALID_SEQ = 0x04
        TIMEOUT = 0x05
        CHANNEL_BUSY = 0x06
        LOCK_REQUIRED = 0x0A
        INVALID_CHANNEL = 0x0B
        CBOR_UNEXPECTED_TYPE = 0x11
        INVALID_CBOR = 0x12
        MISSING_PARAMETER = 0x14
        LIMIT_EXCEEDED = 0x15
        UNSUPPORTED_EXTENSION = 0x16
        CREDENTIAL_EXCLUDED = 0x19
        PROCESSING = 0x21
        INVALID_CREDENTIAL = 0x22
        USER_ACTION_PENDING = 0x23
        OPERATION_PENDING = 0x24
        NO_OPERATIONS = 0x25
        UNSUPPORTED_ALGORITHM = 0x26
        OPERATION_DENIED = 0x27
        KEY_STORE_FULL = 0x28
        NOT_BUSY = 0x29
        NO_OPERATION_PENDING = 0x2A
        UNSUPPORTED_OPTION = 0x2B
        INVALID_OPTION = 0x2C
        KEEPALIVE_CANCEL = 0x2D
        NO_CREDENTIALS = 0x2E
        USER_ACTION_TIMEOUT = 0x2F
        NOT_ALLOWED = 0x30
        PIN_INVALID = 0x31
        PIN_BLOCKED = 0x32
        PIN_AUTH_INVALID = 0x33
        PIN_AUTH_BLOCKED = 0x34
        PIN_NOT_SET = 0x35
        PIN_REQUIRED = 0x36
        PIN_POLICY_VIOLATION = 0x37
        PIN_TOKEN_EXPIRED = 0x38
        REQUEST_TOO_LARGE = 0x39
        ACTION_TIMEOUT = 0x3A
        UP_REQUIRED = 0x3B
        OTHER = 0x7F
        SPEC_LAST = 0xDF
        EXTENSION_FIRST = 0xE0
        EXTENSION_LAST = 0xEF
        VENDOR_FIRST = 0xF0
        VENDOR_LAST = 0xFF

        def __str__(self):
            return '0x%02X - %s' % (self.value, self.name)

    def __init__(self, code):
        try:
            code = CtapError.ERR(code)
            message = 'CTAP error: %s' % code
        except ValueError:
            message = 'CTAP error: 0x%02X' % code
        self.code = code
        super(CtapError, self).__init__(message)


class _SingleEvent(object):
    def __init__(self):
        self.flag = False

    def is_set(self):
        if not self.flag:
            self.flag = True
            return False
        return True


class CtapHidDevice(CtapDevice):
    """
    CtapDevice implementation using the HID transport.
    """

    def __init__(self, descriptor, dev):
        self.descriptor = descriptor
        self._dev = dev

    def __repr__(self):
        return 'CtapHidDevice(%s)' % self.descriptor['path']

    @property
    def version(self):
        return self._dev.u2fhid_version

    @property
    def device_version(self):
        return self._dev.device_version

    @property
    def capabilities(self):
        return self._dev.capabilities

    def call(self, cmd, data=b'', event=None):
        event = event or Event()
        self._dev.InternalSend(TYPE_INIT | cmd, bytearray(data))
        while not event.is_set():
            status, resp = self._dev.InternalRecv()
            status ^= TYPE_INIT
            if status == cmd:
                return bytes(resp)
            elif status == CTAPHID.ERROR:
                raise CtapError(resp[0])
            elif status == CTAPHID.KEEPALIVE:
                continue
            else:
                raise CtapError(CtapError.ERR.INVALID_COMMAND)

        self.call(CTAPHID.CANCEL, b'', _SingleEvent())
        raise CtapError(CtapError.ERR.KEEPALIVE_CANCEL)

    def wink(self):
        self.call(CTAPHID.WINK)

    def ping(self, msg=b'Hello U2F'):
        return self.call(CTAPHID.PING, msg)

    def lock(self, lock_time=10):
        self.call(CTAPHID.LOCK, struct.pack('>B', lock_time))

    @classmethod
    def list_devices(cls, selector=hidtransport.HidUsageSelector):
        for d in hidtransport.hid.Enumerate():
            if selector(d):
                try:
                    dev = hidtransport.hid.Open(d['path'])
                    yield cls(d, hidtransport.UsbHidTransport(dev))
                except OSError:
                    # Insufficient permissions to access device
                    pass
