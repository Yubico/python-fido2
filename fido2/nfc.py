
from .ctap import CtapDevice
from .hid import CAPABILITY, CTAPHID
from .pcsc import PCSCDevice, bytes_from_int
from smartcard.Exceptions import CardConnectionException, NoCardException


class CardSelectException(Exception):
    """can't select u2f/fido2 application on the card"""
    pass


class CtapNfcDevice(CtapDevice):
    """
    CtapDevice implementation using the pcsc NFC transport.

    :cvar descriptor: Device descriptor.
    """

    def __init__(self, descriptor, dev, no_card=False):
        self.descriptor = descriptor
        self._dev = dev

        # init card
        if not no_card:
            self._dev.connect()
            self._ats = self._dev.get_ats()
            if self._ats is None or \
               len(self._ats) == 0:
                raise NoCardException('No ATS')

            self._app_select_result, sw1, sw2 = self._dev.select_applet()
            if self._app_select_result is None or \
               len(self._app_select_result) == 0 or \
               sw1 != 0x90:
                raise CardSelectException('Select error')

        return

    def get_pcsc_device(self):
        return self._dev

    def __repr__(self):
        return 'CtapNfcDevice(%s)' % self.descriptor

    @property
    def version(self):
        """CTAP NFC protocol version.
        :rtype: int
        """
        ver = self.call(CTAPHID.CBOR, b'\x04')
        if len(ver) > 0:
            return 2
        else:
            return 1

    @property
    def device_version(self):
        """Device version number."""
        return 'ATS: ' + self._ats

    @property
    def capabilities(self):
        """Capabilities supported by the device."""
        return CAPABILITY.CBOR

    def call(self, cmd, data=b'', event=None, on_keepalive=None):
        if cmd == CTAPHID.MSG:
            apdu = data[7:]
            apdu = apdu[:-2]
            if data.find(b'\x00\x01') == 0:
                apdu = b'\x00\x01\x03\x00' + bytes_from_int(len(apdu)) + apdu
            else:
                apdu = data[0:4] + bytes([len(apdu)]) + apdu

            apdu += b'\x00'

            resp, sw1, sw2 = self._dev.apdu_exchange(apdu)
            return resp + bytes_from_int(sw1) + bytes_from_int(sw2)

        if cmd == CTAPHID.CBOR:
            apdu = data
            apdu = b'\x80\x10\x00\x00' + bytes_from_int(len(apdu)) + apdu
            apdu += b'\x00'

            resp, sw1, sw2 = self._dev.apdu_exchange(apdu)
            return resp

        if cmd == CTAPHID.PING:
            return data

        if cmd == CTAPHID.WINK:
            return data

        return b''

    def ping(self, msg=b'Hello FIDO'):
        """Sends data to the authenticator, which echoes it back.

        :param msg: The data to send.
        :return: The response from the authenticator.
        """
        return self.call(CTAPHID.PING, msg)

    def lock(self, lock_time=10):
        return

    @classmethod  # selector='CL'
    def list_devices(cls, selector='', pcsc_device=PCSCDevice):
        """
        Returns list of readers in the system. Iterator.
        :param selector:
        :param pcsc_device: device to work with.  PCSCDevice by default.
        :return: iterator. next reader
        """
        for v in pcsc_device.list_devices(selector):
            try:
                pd = pcsc_device(v)
                yield cls(v.name, pd)
            except CardConnectionException:
                pass
        return
