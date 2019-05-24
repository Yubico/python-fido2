
import logging
from smartcard.Exceptions import NoCardException
from smartcard.System import readers
import binascii

APDULogging = False


class PCSCDevice:
    """
    PCSC CTAP reader
    """

    def __init__(self, reader):
        """
        Class PCSCDevice init
        :param reader: link to pcsc reader
        """

        self.ats = b''
        self.reader = reader
        self.connection = None
        self.logger = PCSCDevice.get_logger()
        return

    @classmethod
    def get_logger(cls):
        logger = logging.getLogger('_fido2.pcsc')
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        if APDULogging:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.CRITICAL)
        return logger

    @classmethod
    def list_devices(cls, selector=''):
        """
        Returns list of pcsc readers connected to the system. Iterator.
        :param selector: text selector. select only readers that have it in name
        :return: iterator. next pcsc device.
        """

        for reader in readers():
            if reader.name.find(selector) >= 0:
                yield reader

        PCSCDevice.get_logger().debug('No more devices found.')
        return

    def _transmit(self, apdu, protocol=None):
        result, sw1, sw2 = self.connection.transmit(list(apdu), protocol)
        result = bytes(result)
        return result, sw1, sw2

    def connect(self):
        """
        connect to reader
        :return: True if OK
        """

        try:
            if self.connection is None:
                self.connection = self.reader.createConnection()
            self.connection.connect()  # protocol=CardConnection.T0_protocol
            if APDULogging:
                self.logger.debug('protocol %d', self.connection.getProtocol())
        except Exception as e:
            self.logger.error('Error reader connect: %s', e)
            return False

        return True

    def get_ats(self):
        """
        get Answer To Select (iso14443-4) of NFC device
        :return: byte string. ATS
        """

        try:
            self.ats = bytes(self.connection.getATR())
            if APDULogging:
                self.logger.debug('ats %s', self.ats.hex())
        except NoCardException:
            self.logger.error('No card inserted')
            self.ats = b''
        return self.ats

    def select_applet(self, aid=binascii.unhexlify('A0000006472F0001')):
        """
        Select applet on smart card
        :param aid: byte string. applet id. u2f aid by default.
        :return: byte string. return value of select command
        """

        res, sw1, sw2 = self.apdu_exchange_ex(b'\x00\xA4\x04\x00', aid)
        return res, sw1, sw2

    def apdu_exchange_ex(self, cmd, data):
        """
        Exchange data with smart card. Calculates length of data and adds `Le`
        :param cmd:  byte string. apdu command. usually have 4 bytes long
        :param data:  byte string. apdu data. may be empty string
        :return: byte string. response from card
        """
        return self.apdu_exchange(cmd + bytes([len(data)]) + data + b'\0')

    def apdu_exchange(self, apdu):
        """
        Exchange data with smart card
        :param apdu: byte string. data to exchange with card
        :return: byte string. response from card
        """

        response = b''
        sw1, sw2 = 0, 0

        if APDULogging:
            self.logger.debug('apdu %s', apdu.hex())

        if (self.connection is not None) and (len(self.ats) > 0):
            try:
                response, sw1, sw2 = self._transmit(apdu)
                while sw1 == 0x9F or sw1 == 0x61:
                    lres, sw1, sw2 = self._transmit(b'\x00\xC0\x00\x00' +
                                                    bytes([sw2]))
                    response += lres

            except Exception as e:
                self.logger.error('apdu exchange error: %s', e)

        if APDULogging:
            self.logger.debug('response %s %s',
                              '[' + hex((sw1 << 8) + sw2) + ']',
                              response.hex())
        return response, sw1, sw2

    def control_exchange(self, control_data=b'', control_code=3225264):
        """
        Sends control sequence to reader's driver
        :param control_data: byte string. data to send to driver
        :param control_code: int. code to send to reader driver.
        :return: byte string. response
        """
        response = b''

        if APDULogging:
            self.logger.debug('control %s', control_data.hex())

        if self.connection is not None:
            try:
                response = self.connection.control(control_code,
                                                   list(control_data))
                response = bytes(response)
            except Exception as e:
                self.logger.error('control error: ' + str(e))

        if APDULogging:
            self.logger.debug('response %s', response.hex())
        return response
