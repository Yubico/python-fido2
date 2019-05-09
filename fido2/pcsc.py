
import abc
import binascii

UseNFC = False


class _PCSCDevice:
    '''

    '''

    def __init__(self):
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

        :param aid: byte string. applet id
        :return: byte string. return value of select command
        '''

    @abc.abstractmethod
    def APDUExchange(self, apdu):
        '''

        :param apdu:
        :return:
        '''

    @abc.abstractmethod
    def LED(self, red=False, green=False):
        '''

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
    from smartcard.scard import *

    class PCSCDevice(_PCSCDevice):
        def __init__(self):
            self.init = False
            self.ATS = b""
            return

        def GetATS(self):
            self.ATS = b""
            return self.ATS

        def SelectApplet(self, aid=binascii.unhexlify("A0000006472F0001")):
            if not self.init:
                self.GetATS()

            return self.APDUExchangeEx(b"\x00\xA4\x04\x00", aid)

        def APDUExchangeEx(self, cmd, data):
            return self.APDUExchange(cmd + bytes([len(data)]) + data + b"\0")

        def APDUExchange(self, apdu):
            return b""

        def LED(self, red=False, green=False):
            return

