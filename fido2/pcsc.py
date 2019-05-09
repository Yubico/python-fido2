
from .ctap import CtapDevice, CtapError
from .hid import CAPABILITY, CTAPHID

import struct


class CtapNFCDevice(CtapDevice):
    """
    CtapDevice implementation using the NFC transport.

    :cvar descriptor: Device descriptor.
    """

    def __init__(self, descriptor, dev):
        self.descriptor = descriptor
        self._dev = dev

    def __repr__(self):
        return 'CtapNFCDevice(%s)' % self.descriptor

    @property
    def version(self):
        """CTAP NFC protocol version.

        :rtype: Tuple[int, int, int]
        """
        #return self._dev.u2fhid_version
        return [1, 0, 0]

    @property
    def device_version(self):
        """Device version number."""
        #return self._dev.device_version
        return "ATS: "

    @property
    def capabilities(self):
        """Capabilities supported by the device."""
        return CAPABILITY.CBOR

    def call(self, cmd, data=b'', event=None, on_keepalive=None):
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
    def list_devices(cls, selector="CL"):
        '''
        for d in hidtransport.hid.Enumerate():
            if selector(d):
                try:
                    dev = hidtransport.hid.Open(d['path'])
                    yield cls(d, hidtransport.UsbHidTransport(dev))
                except OSError:
                    # Insufficient permissions to access device
                    pass
        '''
        return
