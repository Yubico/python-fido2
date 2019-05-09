
import abc
import binascii

UseNFC = False


def NFCEnable():
    global UseNFC
    UseNFC = True


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


if not UseNFC:
    class PCSCDevice(_PCSCDevice):
        def GetATS(self):
            return b""

        def SelectApplet(self, aid):
            return b""

        def APDUExchange(self, apdu):
            return b""

        def LED(self, red=False, green=False):
            return

else:
    from smartcard.Exceptions import NoCardException, SWException
    from smartcard.System import readers

    class PCSCDevice(_PCSCDevice):
        def __init__(self, reader):
            self.init = False
            self.ATS = b""
            self.reader = reader
            self.connection = None
            return

        def GetATS(self):
            try:
                if self.connection is None:
                    self.connection = self.reader.createConnection()
                self.connection.connect()
                self.init = True
                self.ATS = self.connection.getATR()
                print("ats", self.reader, self.connection.getATR().hex())
            except NoCardException:
                print("ats", self.reader, 'no card inserted')
                self.ATS = b""
            return self.ATS

        def SelectApplet(self, aid=binascii.unhexlify("A0000006472F0001")):
            if not self.init:
                self.GetATS()

            return self.APDUExchangeEx(b"\x00\xA4\x04\x00", aid)

        def APDUExchangeEx(self, cmd, data):
            return self.APDUExchange(cmd + bytes([len(data)]) + data + b"\0")

        def APDUExchange(self, apdu):
            response = b""
            sw1, sw2 = 0, 0
            if (self.connection is not None) and (len(self.ATS) > 0):
                try:
                    lres, sw1, sw2 = self.connection.transmit(list(apdu))
                    response = bytes(lres)

                    while sw1 == 0x9F or sw1 == 0x61:
                        lres, sw1, sw2 = self.connection.transmit(list(b"\x00\xC0\x00\x00") + [sw2])
                        response += bytes(lres)

                except SWException as e:
                    print("ERROR: " + str(e))

            return response, sw1, sw2

        def LED(self, red=False, green=False, blink=0):
            if (self.connection is not None) and (len(self.ATS) > 0):
                try:
                    cbyte = 0b00001100 + 0b01 if red else 0b00 + 0b10 if green else 0b00
                    if blink > 0:
                        cbyte |= 0b00110000 | ((cbyte << 6) & 0xc0)
                    apdu = b"\xff\x00\x40" + bytes(cbyte & 0xff) + b"\4" + b"\5\3" + bytes(blink) + "\0"
                    self.connection.transmit(list(apdu))

                except SWException as e:
                    print("ERROR: " + str(e))
                    pass
            return

