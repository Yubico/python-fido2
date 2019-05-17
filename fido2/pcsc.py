
from smartcard.Exceptions import NoCardException
from smartcard.System import readers
import binascii
from enum import IntEnum, unique

APDULogging = False


@unique
class STATUS(IntEnum):
    INIT = 1
    GOTATS = 2
    SELECTED = 3


class PCSCDevice:
    """
    PCSC CTAP reader
    """

    def __init__(self, reader):
        """
        Class PCSCDevice init
        :param reader: link to pcsc reader
        """

        self.state = STATUS.INIT
        self.ats = b''
        self.reader = reader
        self.connection = None
        return

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

        print('No more devices found.')
        return

    def _transmit(self, apdu, protocol=None):
        result, sw1, sw2 = self.connection.transmit(list(apdu), protocol)
        result = bytes(result)
        return result, sw1, sw2

    def get_ats(self):
        """
        get Answer To Select (iso14443-4) of NFC device
        :return: byte string. ATS
        """

        try:
            if self.connection is None:
                self.connection = self.reader.createConnection()
            self.connection.connect()  # protocol=CardConnection.T0_protocol
            if APDULogging:
                print('protocol', self.connection.getProtocol())
            self.state = STATUS.GOTATS
            self.ats = bytes(self.connection.getATR())
            if APDULogging:
                print('ats', self.ats.hex())
        except NoCardException:
            print('No card inserted')
            self.ats = b''
        return self.ats

    def select_applet(self, aid=binascii.unhexlify('A0000006472F0001')):
        """
        Select applet on smart card
        :param aid: byte string. applet id. u2f aid by default.
        :return: byte string. return value of select command
        """

        if self.state != STATUS.GOTATS:
            self.get_ats()

        res, sw1, sw2 = self.apdu_exchange_ex(b'\x00\xA4\x04\x00', aid)
        if sw1 == 0x90:
            self.state = STATUS.SELECTED
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
            print('apdu', apdu.hex())

        if (self.connection is not None) and (len(self.ats) > 0):
            try:
                response, sw1, sw2 = self._transmit(apdu)
                while sw1 == 0x9F or sw1 == 0x61:
                    lres, sw1, sw2 = self._transmit(b'\x00\xC0\x00\x00' +
                                                    bytes([sw2]))
                    response += lres

            except Exception as e:
                print('ERROR: ' + str(e))

        if APDULogging:
            print('response',
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
            print('control', control_data.hex())

        if self.connection is not None:
            try:
                response = self.connection.control(control_code,
                                                   list(control_data))
                response = bytes(response)
            except Exception as e:
                print('Control error: ' + str(e))

        if APDULogging:
            print('response', response.hex())
        return response


class Acr122uPcscDevice(PCSCDevice):
    def reader_version(self):
        """
        Get reader's version from reader
        :return: string. Reader's version
        """

        if self.state != STATUS.GOTATS:
            self.get_ats()

        if self.connection is not None:
            try:
                result, sw1, sw2 = self.apdu_exchange(b'\xff\x00\x48\x00\x00')
                if len(result) > 0:
                    str_result = result + bytes([sw1]) + bytes([sw2])
                    str_result = str_result.decode('utf-8')
                    return str_result
            except Exception as e:
                print('Get version error:', e)
                pass
        return 'n/a'

    def led_control(self, red=False, green=False,
                    blink_count=0, red_end_blink=False, green_end_blink=False):
        """
        Reader's led control
        :param red: boolean. red led on
        :param green: boolean. green let on
        :param blink_count: int. if needs to blink value > 0. blinks count
        :param red_end_blink: boolean. state of red led at the end of blinking
        :param green_end_blink: boolean. state of green led at the end of blinking
        :return:
        """

        if self.state != STATUS.GOTATS:
            self.get_ats()

        if self.connection is not None:
            try:
                if blink_count > 0:
                    cbyte = 0b00001100 + \
                            (0b01 if red_end_blink else 0b00) + \
                            (0b10 if green_end_blink else 0b00)
                    cbyte |= (0b01000000 if red else 0b00000000) + \
                             (0b10000000 if green else 0b00000000)
                else:
                    cbyte = 0b00001100 + \
                            (0b01 if red else 0b00) + \
                            (0b10 if green else 0b00)

                apdu = b'\xff\x00\x40' + \
                       bytes([cbyte & 0xff]) + \
                       b'\4' + b'\5\3' + \
                       bytes([blink_count]) + \
                       b'\0'
                self.apdu_exchange(apdu)

            except Exception as e:
                print('LED control error:', e)
                pass
        return


class Acr1252uPcscDevice(PCSCDevice):
    def reader_version(self):
        if self.state != STATUS.GOTATS:
            self.get_ats()

        if self.connection is not None:
            try:
                # control codes:
                # 3225264 - magic number!!!
                # 0x42000000 + 3500 - cross platform way
                res = self.control_exchange(b'\xe0\x00\x00\x18\x00', 3225264)

                if len(res) > 0 and res.find(b'\xe1\x00\x00\x00') == 0:
                    reslen = res[4]
                    if reslen == len(res) - 5:
                        strres = res[5:5+reslen].decode('utf-8')
                        return strres
            except Exception as e:
                print('Get version error:', e)
                pass
        return 'n/a'

    def reader_serial_number(self):
        if self.state != STATUS.GOTATS:
            self.get_ats()

        if self.connection is not None:
            try:
                res = self.control_exchange(b'\xe0\x00\x00\x33\x00')

                if len(res) > 0 and res.find(b'\xe1\x00\x00\x00') == 0:
                    reslen = res[4]
                    if reslen == len(res) - 5:
                        strres = res[5:5+reslen].decode('utf-8')
                        return strres
            except Exception as e:
                print('Get serial number error:', e)
                pass
        return 'n/a'

    def led_control(self, red=False, green=False):
        if self.state != STATUS.GOTATS:
            self.get_ats()

        if self.connection is not None:
            try:
                cbyte = (0b01 if red else 0b00) + (0b10 if green else 0b00)
                result = self.control_exchange(b'\xe0\x00\x00\x29\x01' +
                                               bytes([cbyte]))

                if len(result) > 0 and result.find(b'\xe1\x00\x00\x00') == 0:
                    result_length = result[4]
                    if result_length == 1:
                        ex_red = bool(result[5] & 0b01)
                        ex_green = bool(result[5] & 0b10)
                        return True, ex_red, ex_green
            except Exception as e:
                print('LED control error:', e)
                pass

        return False, False, False

    def led_status(self):
        if self.state != STATUS.GOTATS:
            self.get_ats()

        if self.connection is not None:
            try:
                result = self.control_exchange(b'\xe0\x00\x00\x29\x00')

                if len(result) > 0 and result.find(b'\xe1\x00\x00\x00') == 0:
                    result_length = result[4]
                    if result_length == 1:
                        ex_red = bool(result[5] & 0b01)
                        ex_green = bool(result[5] & 0b10)
                        return True, ex_red, ex_green
            except Exception as e:
                print('LED status error:', e)
                pass

        return False, False, False

    def get_polling_settings(self):
        if self.state != STATUS.GOTATS:
            self.get_ats()

        if self.connection is not None:
            try:
                res = self.control_exchange(b'\xe0\x00\x00\x23\x00')

                if len(res) > 0 and res.find(b'\xe1\x00\x00\x00') == 0:
                    reslen = res[4]
                    if reslen == 1:
                        return True, res[5]
            except Exception as e:
                print('Get polling settings error:', e)
                pass

        return False, 0

    def set_polling_settings(self, settings):
        if self.state != STATUS.GOTATS:
            self.get_ats()

        if self.connection is not None:
            try:
                res = self.control_exchange(b'\xe0\x00\x00\x23\x01' +
                                            bytes([settings & 0xff]))

                if len(res) > 0 and res.find(b'\xe1\x00\x00\x00') == 0:
                    reslen = res[4]
                    if reslen == 1:
                        return True, res[5]
            except Exception as e:
                print('Set polling settings error:', e)
                pass

        return False, 0

    def get_picc_operation_parameter(self):
        if self.state != STATUS.GOTATS:
            self.get_ats()

        if self.connection is not None:
            try:
                res = self.control_exchange(b'\xe0\x00\x00\x20\x00')

                if len(res) > 0 and res.find(b'\xe1\x00\x00\x00') == 0:
                    reslen = res[4]
                    if reslen == 1:
                        return True, res[5]
            except Exception as e:
                print('Get PICC Operating Parameter error:', e)
                pass

        return False, 0

    def set_picc_operation_parameter(self, param):
        if self.state != STATUS.GOTATS:
            self.get_ats()

        if self.connection is not None:
            try:
                res = self.control_exchange(b'\xe0\x00\x00\x20\x01' +
                                            bytes([param]))

                if len(res) > 0 and res.find(b'\xe1\x00\x00\x00') == 0:
                    reslen = res[4]
                    if reslen == 1:
                        return True, res[5]
            except Exception as e:
                print('Set PICC Operating Parameter error:', e)
                pass

        return False, 0
