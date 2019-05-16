
import abc
import binascii
from enum import IntEnum, unique

UseNFC = False
APDULogging = False

@unique
class STATUS(IntEnum):
    INIT = 1
    GOTATS = 2
    SELECTED = 3

class _PCSCDevice:
    '''
    Abstract version of pcsc reader
    '''

    def __init__(self, reader):
        '''
        Class init
        :param reader: link to pcsc reader
        '''
        self.reader = reader
        return

    @classmethod
    @abc.abstractmethod
    def list_devices(cls, selector=""):
        '''

        :param selector:
        :return: iterator. next pcsc device.
        '''

    @abc.abstractmethod
    def GetATS(self):
        '''
        get Answer To Select (iso14443-4) of NFC device
        :return: byte string. ATS
        '''

    @abc.abstractmethod
    def SelectApplet(self, aid):
        '''
        Select applet on smart card
        :param aid: byte string. applet id
        :return: byte string. return value of select command
        '''

    @abc.abstractmethod
    def APDUExchange(self, apdu):
        '''
        Exchange data with smart card
        :param apdu: byte string. data to exchange with card
        :return: byte string. response from card
        '''

    @abc.abstractmethod
    def LED(self, red=False, green=False):
        '''
        Control LEDs on ACR122U reader and compatible readers from ACS
        :param red: boolean. red led on/off
        :param green: boolean. green led on/off
        :return:
        '''


if not ('UseNFC' in globals()):
    class PCSCDevice(_PCSCDevice):
        @classmethod
        def list_devices(cls, selector=""):
            raise StopIteration

        def GetATS(self):
            return b""

        def SelectApplet(self, aid):
            return b""

        def APDUExchange(self, apdu):
            return b""

        def LED(self, red=False, green=False):
            return

else:
    from smartcard.Exceptions import NoCardException
    from smartcard.System import readers

    class PCSCDevice(_PCSCDevice):
        def __init__(self, reader):
            self.state = STATUS.INIT
            self.ATS = b""
            self.reader = reader
            self.connection = None
            return

        @classmethod
        def list_devices(cls, selector=""):
            for reader in readers():
                if reader.name.find(selector) >= 0:
                    yield reader

            print("No more devices found.")
            return

        def _transmit(self, apdu, protocol=None):
            res, sw1, sw2 = self.connection.transmit(list(apdu), protocol)
            res = bytes(res)
            return res, sw1, sw2

        def GetATS(self):
            try:
                if self.connection is None:
                    self.connection = self.reader.createConnection()
                self.connection.connect()  # protocol=CardConnection.T0_protocol
                if APDULogging:
                    print("protocol", self.connection.getProtocol())
                self.state = STATUS.GOTATS
                self.ATS = bytes(self.connection.getATR())
                if APDULogging:
                    print("ats", self.ATS.hex())
            except NoCardException:
                print("No card inserted")
                self.ATS = b""
            return self.ATS

        def SelectApplet(self, aid=binascii.unhexlify("A0000006472F0001")):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            res, sw1, sw2 = self.APDUExchangeEx(b"\x00\xA4\x04\x00", aid)
            if sw1 == 0x90:
                self.state = STATUS.SELECTED
            return res, sw1, sw2

        def APDUExchangeEx(self, cmd, data):
            return self.APDUExchange(cmd + bytes([len(data)]) + data + b"\0")

        def APDUExchange(self, apdu):
            response = b""
            sw1, sw2 = 0, 0

            if APDULogging:
                print("apdu", apdu.hex())

            if (self.connection is not None) and (len(self.ATS) > 0):
                try:
                    response, sw1, sw2 = self._transmit(apdu)
                    while sw1 == 0x9F or sw1 == 0x61:
                        lres, sw1, sw2 = self._transmit(b"\x00\xC0\x00\x00" + bytes([sw2]))
                        response += lres

                except Exception as e:
                    print("ERROR: " + str(e))

            if APDULogging:
                print("response", "[" + hex((sw1 << 8) + sw2) + "]", response.hex())
            return response, sw1, sw2

        def ControlExchange(self, controlData=b"", controlCode=3225264):
            response = b""

            if APDULogging:
                print("control", controlData.hex())

            if (self.connection is not None):
                try:
                    response = self.connection.control(controlCode, list(controlData))
                    response = bytes(response)
                except Exception as e:
                    print("Control error: " + str(e))

            if APDULogging:
                print("response", response.hex())
            return response

        def LED(self, red=False, green=False, blinkCount=0, redEndBlink=False, greenEndBlink=False):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    if blinkCount > 0:
                        cbyte = 0b00001100 + (0b01 if redEndBlink else 0b00) + (0b10 if greenEndBlink else 0b00)
                        cbyte |= (0b01000000 if red else 0b00000000) + (0b10000000 if green else 0b00000000)
                    else:
                        cbyte = 0b00001100 + (0b01 if red else 0b00) + (0b10 if green else 0b00)

                    apdu = b"\xff\x00\x40" + bytes([cbyte & 0xff]) + b"\4" + b"\5\3" + bytes([blinkCount]) + b"\0"
                    self.APDUExchange(apdu)

                except:
                    pass
            return

        def ReaderVersion(self):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    res, sw1, sw2 = self.APDUExchange(b"\xff\x00\x48\x00\x00")
                    if len(res) > 0:
                        strres = res + bytes([sw1]) + bytes([sw2])
                        strres = strres.decode("utf-8")
                        return strres
                except Exception as e:
                    print("Get version error:", e)
                    pass
            return "n/a"

    class ACR1252UPCSCDevice(PCSCDevice):
        def ReaderVersion(self):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    # control codes:
                    # 3225264 - magic number!!!
                    # 0x42000000 + 3500 - cross platform way
                    res = self.ControlExchange(b"\xe0\x00\x00\x18\x00", 3225264)

                    if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                        reslen = res[4]
                        if reslen == len(res) - 5:
                            strres = res[5:5+reslen].decode("utf-8")
                            return strres
                except Exception as e:
                    print("Get version error:", e)
                    pass
            return "n/a"

        def ReaderSerialNumber(self):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    res = self.ControlExchange(b"\xe0\x00\x00\x33\x00")

                    if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                        reslen = res[4]
                        if reslen == len(res) - 5:
                            strres = res[5:5+reslen].decode("utf-8")
                            return strres
                except Exception as e:
                    print("Get serial number error:", e)
                    pass
            return "n/a"

        def LEDControl(self, red=False, green=False):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    cbyte = (0b01 if red else 0b00) + (0b10 if green else 0b00)
                    res = self.ControlExchange(b"\xe0\x00\x00\x29\x01" + bytes([cbyte]))

                    if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                        reslen = res[4]
                        if reslen == 1:
                            exRed = bool(res[5] & 0b01)
                            exGreen = bool(res[5] & 0b10)
                            return True, exRed, exGreen
                except Exception as e:
                    print("LED control error:", e)
                    pass

            return False, False, False

        def LEDStatus(self):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    res = self.ControlExchange(b"\xe0\x00\x00\x29\x00")

                    if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                        reslen = res[4]
                        if reslen == 1:
                            exRed = bool(res[5] & 0b01)
                            exGreen = bool(res[5] & 0b10)
                            return True, exRed, exGreen
                except Exception as e:
                    print("LED status error:", e)
                    pass

            return False, False, False


        def ReadPollingSettings(self):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    res = self.ControlExchange(b"\xe0\x00\x00\x23\x00")

                    if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                        reslen = res[4]
                        if reslen == 1:
                            return True, res[5]
                except Exception as e:
                    print("Read polling settings error:", e)
                    pass

            return False, 0

        def WritePollingSettings(self, settings):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    res = self.ControlExchange(b"\xe0\x00\x00\x23\x01" + bytes([settings & 0xff]))

                    if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                        reslen = res[4]
                        if reslen == 1:
                            return True, res[5]
                except Exception as e:
                    print("Write polling settings error:", e)
                    pass

            return False, 0

        def ReadPICCOperationParameter(self):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    res = self.ControlExchange(b"\xe0\x00\x00\x20\x00")

                    if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                        reslen = res[4]
                        if reslen == 1:
                            return True, res[5]
                except Exception as e:
                    print("Read PICC Operating Parameter error:", e)
                    pass

            return False, 0

        def WritePICCOperationParameter(self, param):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    res = self.ControlExchange(b"\xe0\x00\x00\x20\x01" + bytes([param]))

                    if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                        reslen = res[4]
                        if reslen == 1:
                            return True, res[5]
                except Exception as e:
                    print("Write PICC Operating Parameter error:", e)
                    pass

            return False, 0
