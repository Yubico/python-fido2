
from .ctap import CtapDevice, CtapError
from .hid import CAPABILITY, CTAPHID
from .pcsc import PCSCDevice, NFCEnable, STATUS

import struct


class CtapNFCDevice(CtapDevice):
    """
    CtapDevice implementation using the NFC transport.

    :cvar descriptor: Device descriptor.
    """

    def __init__(self, descriptor, dev):
        NFCEnable()

        self.descriptor = descriptor
        self._dev = dev

    def __repr__(self):
        return 'CtapNFCDevice(%s)' % self.descriptor

    @property
    def version(self):
        """CTAP NFC protocol version.

        :rtype: Tuple[int, int, int]
        """
        return [1, 0, 0]

    @property
    def device_version(self):
        """Device version number."""
        return "ATS: " + self._dev.GetATS()

    @property
    def capabilities(self):
        """Capabilities supported by the device."""
        return CAPABILITY.CBOR

    def call(self, cmd, data=b'', event=None, on_keepalive=None):
        if self._dev.state != STATUS.SELECTED:
            self._dev.SelectApplet()

        if cmd == CTAPHID.MSG:
            apdu = data[7:]
            apdu = apdu[:-2]
            if data.find(b"\x00\x01") == 0:
                apdu = b"\x00\x01\x03\x00" + bytes([len(apdu)]) + apdu
            else:
                apdu = data[0:4] + bytes([len(apdu)]) + apdu

            apdu += b"\x00"
            print("apdu changed", apdu.hex())
            return self._dev.APDUExchange(apdu)

        if cmd == CTAPHID.CBOR:
            apdu = data
            apdu = b"\x80\x10\x00\x00" + bytes([len(apdu)]) + apdu
            apdu += b"\x00"
            print("apdu CBOR changed", apdu.hex())
            return self._dev.APDUExchange(apdu)

        if cmd == CTAPHID.PING:
            return data

        if cmd == CTAPHID.WINK:
            return data

        return b""

    def ping(self, msg=b'Hello FIDO'):
        """Sends data to the authenticator, which echoes it back.

        :param msg: The data to send.
        :return: The response from the authenticator.
        """
        return self.call(CTAPHID.PING, msg)

    def lock(self, lock_time=10):
        return

    @classmethod
    def list_devices(cls, selector=""):  # selector="CL"
        NFCEnable()
        for v in PCSCDevice.list_devices(selector):
            print(v)
            yield cls(v.name, PCSCDevice(v))
        raise StopIteration
