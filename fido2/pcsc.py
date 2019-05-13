
import abc
import binascii
from enum import IntEnum, unique

UseNFC = False

def NFCEnable():
    global UseNFC
    UseNFC = True

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
            print("abstract!!!!.")
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
    from smartcard.CardConnection import CardConnection

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
                self.connection.connect()
                self.state = STATUS.GOTATS
                self.ATS = bytes(self.connection.getATR())
                print("ats", self.reader, self.ATS.hex())
            except NoCardException:
                print("ats", self.reader, 'no card inserted')
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
            #print("apdu", apdu.hex())
            if (self.connection is not None) and (len(self.ATS) > 0):
                try:
                    response, sw1, sw2 = self._transmit(apdu)

                    while sw1 == 0x9F or sw1 == 0x61:
                        lres, sw1, sw2 = self._transmit(b"\x00\xC0\x00\x00" + bytes([sw2]))
                        response += lres

                except Exception as e:
                    print("ERROR: " + str(e))

            #print("response", response.hex())
            return response, sw1, sw2

        def LED(self, red=False, green=False, blink=0):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    cbyte = 0b00001100 + 0b01 if red else 0b00 + 0b10 if green else 0b00
                    if blink > 0:
                        cbyte |= 0b00110000 | ((cbyte << 6) & 0xc0)
                    apdu = b"\xff\x00\x40" + bytes(cbyte & 0xff) + b"\4" + b"\5\3" + bytes(blink) + b"\0"
                    self._transmit(apdu)

                except:
                    pass
            return

        def ReaderVersion(self):
            if self.state != STATUS.GOTATS:
                self.GetATS()

            if self.connection is not None:
                try:
                    print("start:", self.state, self.connection)
                    res = self.connection.control(3500, list(b"\xff\x00\x48\x00\x00"))
                    print("res:", res)

                    sw1,sw1 = 0,0
                    print(f"sw1: {sw1}")
                    if len(res) > 0:
                        strres = res + bytes(sw1) + bytes(sw2)
                        strres = strres.decode("utf-8")
                        print("version: " + strres)
                        return strres
                except Exception as e:
                    print("err:", e)
                    pass
            return "n/a"

