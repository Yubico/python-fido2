# Copyright (c) 2019 Yubico AB
# Copyright (c) 2019 Oleg Moiseenko
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Sample work with reader:
ACR-122U-SAM or touchatag
drivers and manual link:
www.acs.com.hk/en/driver/100/acr122u-nfc-reader-with-sam-slot-proprietary/
"""

import time
import six

from fido2.utils import sha256
from fido2.ctap1 import CTAP1

from smartcard.Exceptions import CardConnectionException
from fido2.pcsc import CtapPcscDevice


class Acr122uSamPcscDevice(CtapPcscDevice):
    def __init__(self, connection, name):
        self.ats = b""
        self.vparity = False
        self.max_block_len = 29

        try:
            super().__init__(connection, name)
        except (CardConnectionException, ValueError):
            pass
        except Exception as e:
            print(e.__class__)

        # setup reader
        if not self.set_auto_iso14443_4_activation():
            raise Exception("Set automatic iso-14443-4 activation error")

        if not self.set_default_retry_timeout():
            raise Exception("Set default retry timeout error")

        self.ats = self.get_ats()
        if self.ats == b"":
            raise Exception("No card in field")

        self._select()

    def apdu_plain(self, apdu, protocol=None):
        """Exchange data with reader.

        :param apdu: byte string. data to exchange with card
        :param protocol: protocol to exchange with card. usually set by default
        :return: byte string. response from card
        """

        # print('>> %s' % b2a_hex(apdu))
        resp, sw1, sw2 = self._conn.transmit(list(six.iterbytes(apdu)), protocol)
        response = bytes(bytearray(resp))
        # print('<< [0x%04x] %s' % (sw1 * 0x100 + sw2, b2a_hex(response)))

        return response, sw1, sw2

    def pseudo_apdu_ex(self, apdu, protocol=None):
        req = b"\xff\x00\x00\x00" + bytes([len(apdu) & 0xFF]) + apdu
        resp, sw1, sw2 = self.apdu_plain(req, protocol)
        if sw1 != 0x61:
            return resp, sw1, sw2
        return self.apdu_plain(b"\xff\xc0\x00\x00" + bytes([sw2]), protocol)

    # override base method
    # commands in PN 532 User manual (UM0701-02)
    # page 178. 7.4.5 DEP chaining mechanism
    # page 136. 7.3.9 InCommunicateThru
    # chaining ISO 14443-4:2001
    # page 20. 7.5.2 Chaining
    def apdu_exchange(self, apdu, protocol=None):
        all_response = b""
        alen = 0
        while True:
            vapdu = apdu[alen : alen + self.max_block_len]
            # input chaining
            chaining = alen + len(vapdu) < len(apdu)
            vb = 0x02 | (0x01 if self.vparity else 0x00) | (0x10 if chaining else 0x00)

            # 7.3.9 InCommunicateThru
            resp, sw1, sw2 = self.pseudo_apdu_ex(
                b"\xd4\x42" + bytes([vb]) + vapdu, protocol
            )
            self.vparity = not self.vparity

            if len(resp) > 2 and resp[2] > 0:
                print("Error: 0x%02x" % resp[2])
                return b"", 0x6F, resp[2]
            if sw1 != 0x90 or len(resp) < 3 or resp[0] != 0xD5 or resp[1] != 0x43:
                return b"", 0x67, 0x00

            alen += len(vapdu)

            if not chaining:
                break

        if len(resp) > 3:
            if resp[3] & 0x10 == 0:
                return resp[4:-2], resp[-2], resp[-1]
            else:
                if resp[3] != 0xF2:
                    all_response = resp[4:]
        else:
            return b"", 0x90, 0x00

        while True:
            if len(resp) > 3 and resp[3] == 0xF2:
                # WTX
                answer = resp[3:5]
            else:
                # ACK
                answer = bytes([0xA2 | (0x01 if self.vparity else 0x00)])
                self.vparity = not self.vparity

            # 7.3.9 InCommunicateThru
            resp, sw1, sw2 = self.pseudo_apdu_ex(b"\xd4\x42" + answer, protocol)
            if len(resp) > 2 and resp[2] > 0:
                print("Error: 0x%02x" % resp[2])
                return b"", 0x6F, resp[2]
            if sw1 != 0x90 or len(resp) < 3 or resp[0] != 0xD5 or resp[1] != 0x43:
                return b"", 0x67, 0x00

            response_chaining = len(resp) > 3 and resp[3] & 0x10 != 0

            # if I block
            if len(resp) > 3 and resp[3] & 0xE0 == 0x00:
                all_response += resp[4:]

            if not response_chaining:
                break

        return all_response[:-2], resp[-2], resp[-1]

    def get_ats(self, verbose=False):
        self.field_reset()
        self.ats = b""
        resp, sw1, sw2 = self.pseudo_apdu_ex(b"\xd4\x4a\x01\x00")
        if sw1 == 0x90 and len(resp) > 8 and resp[2] > 0x00:
            if verbose:
                print("ATQA 0x%02x%02x" % (resp[4], resp[5]))
                print("SAK 0x%02x" % resp[6])
            uid_len = resp[7]
            if verbose:
                print("UID [%d] %s" % (uid_len, resp[8 : 8 + uid_len].hex()))
            self.ats = resp[8 + uid_len :]
            if verbose:
                print("ATS [%d] %s" % (len(self.ats), self.ats.hex()))
            self.vparity = False
            return self.ats
        return b""

    def set_default_retry_timeout(self):
        result, sw1, sw2 = self.pseudo_apdu_ex(b"\xd4\x32\x05\x00\x00\x00")
        if sw1 != 0x90 or sw2 != 0x00 or result != b"\xd5\x33":
            print("set default retry time error")
            return False

        # 14443 timeout. UM0701-02 PN432 user manual. page 101.
        # RFU, fATR_RES_Timeout, fRetryTimeout
        # 0b 102ms, 0c - 204ms, 0d - 409ms, 0f - 1.6s
        result, sw1, sw2 = self.pseudo_apdu_ex(b"\xd4\x32\x02\x00\x0c\x0f")
        if sw1 != 0x90 or sw2 != 0x00 or result != b"\xd5\x33":
            print("set fRetryTimeout error")
            return False
        return True

    def set_auto_iso14443_4_activation(self, activate=True):
        result, sw1, sw2 = self.pseudo_apdu_ex(
            b"\xd4\x12" + bytes([0x34 if activate else 0x24])
        )
        if sw1 != 0x90 or sw2 != 0x00 or result != b"\xd5\x13":
            print("set automatic iso-14443-4 activation error")
            return False
        return True

    def field_control(self, field_on=True):
        result, sw1, sw2 = self.pseudo_apdu_ex(
            b"\xd4\x32\x01" + bytes([0x01 if field_on else 0x00])
        )
        if sw1 != 0x90 or sw2 != 0x00 or result != b"\xd5\x33":
            print("set field state error")
            return False
        return True

    def field_reset(self):
        self.led_control(True, False)
        result = self.field_control(False)
        time.sleep(0.2)
        result |= self.field_control(True)
        self.led_control()
        return result

    def reader_version(self):
        """
        Get reader's version from reader
        :return: string. Reader's version
        """

        try:
            result, sw1, sw2 = self.apdu_plain(b"\xff\x00\x48\x00\x00")
            if len(result) > 0:
                str_result = result + bytes([sw1]) + bytes([sw2])
                str_result = str_result.decode("utf-8")
                return str_result
        except Exception as e:
            print("Get version error:", e)
        return "n/a"

    def led_control(
        self,
        red=False,
        green=False,
        blink_count=0,
        red_end_blink=False,
        green_end_blink=False,
    ):
        """
        Reader's led control
        :param red: boolean. red led on
        :param green: boolean. green let on
        :param blink_count: int. if needs to blink value > 0. blinks count
        :param red_end_blink: boolean.
        state of red led at the end of blinking
        :param green_end_blink: boolean.
        state of green led at the end of blinking
        :return:
        """

        try:
            if blink_count > 0:
                cbyte = (
                    0b00001100
                    + (0b01 if red_end_blink else 0b00)
                    + (0b10 if green_end_blink else 0b00)
                )
                cbyte |= (0b01000000 if red else 0b00000000) + (
                    0b10000000 if green else 0b00000000
                )
            else:
                cbyte = 0b00001100 + (0b01 if red else 0b00) + (0b10 if green else 0b00)

            apdu = (
                b"\xff\x00\x40"
                + bytes([cbyte & 0xFF])
                + b"\4"
                + b"\5\3"
                + bytes([blink_count])
                + b"\0"
            )
            self.apdu_plain(apdu)

        except Exception as e:
            print("LED control error:", e)


dev = next(Acr122uSamPcscDevice.list_devices())

print("CONNECT: %s" % dev)
print("version: %s" % dev.reader_version())
print("atr: %s" % dev.get_atr().hex())
print("ats: %s" % dev.ats.hex())

# uncomment if you want to see parameters from card's selection
# dev.get_ats(True)
# dev._select()

dev.led_control(False, True, 0)

chal = sha256(b"AAA")
appid = sha256(b"BBB")
ctap1 = CTAP1(dev)
print("ctap1 version:", ctap1.get_version())

reg = ctap1.register(chal, appid)
print("u2f register:", reg)
reg.verify(appid, chal)
print("Register message verify OK")

auth = ctap1.authenticate(chal, appid, reg.key_handle)
print("u2f authenticate: ", auth)
res = auth.verify(appid, chal, reg.public_key)
print("Authenticate message verify OK")

dev.led_control()
