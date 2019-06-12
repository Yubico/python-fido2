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

from __future__ import absolute_import, unicode_literals

import logging
from smartcard.Exceptions import SmartcardException
from smartcard.System import readers
from binascii import b2a_hex
import struct
import six

APDULogging = True


class PCSCDevice(object):
    """
    PCSC CTAP reader
    """

    def __init__(self, reader):
        """
        Class PCSCDevice init
        :param reader: link to pcsc reader
        """

        self.reader = reader
        self.connection = self.reader.createConnection()
        self.logger = PCSCDevice.get_logger()

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

    def _transmit(self, apdu, protocol=None):
        resp, sw1, sw2 = self.connection.transmit(list(six.iterbytes(apdu)))
        return bytes(bytearray(resp)), sw1, sw2

    def connect(self):
        """
        connect to reader
        :return: True if OK
        """

        try:
            self.connection.connect()  # protocol=CardConnection.T0_protocol
            if APDULogging:
                self.logger.debug('protocol %d', self.connection.getProtocol())
        except SmartcardException as e:
            self.logger.error('Error reader connect: %s', e)
            return False

        return True

    def select_applet(self, aid):
        """
        Select applet on smart card
        :param aid: byte string. applet id.
        :return: byte string. return value of select command
        """

        apdu = b'\x00\xa4\x04\x00' + struct.pack('!B', len(aid)) + aid + b'\x00'
        return self.apdu_exchange(apdu)

    def apdu_exchange(self, apdu):
        """
        Exchange data with smart card
        :param apdu: byte string. data to exchange with card
        :return: byte string. response from card
        """

        # Re-encode extended APDUs as short:
        if len(apdu) >= 7 and six.indexbytes(apdu, 4) == 0:
            data_len = struct.unpack('!H', apdu[5:7])[0]
            if data_len:  # apdu case 4
                apdu = apdu[:4] + struct.pack('!B', data_len) + \
                    apdu[7:7 + data_len] + b'\x00'
            else:  # apdu case 2
                apdu = apdu[:4] + b'\x00'

        response = b''
        sw1, sw2 = 0, 0

        if APDULogging:
            self.logger.debug('apdu %s', b2a_hex(apdu))

        try:
            response, sw1, sw2 = self._transmit(apdu)
            while sw1 == 0x61:
                lres, sw1, sw2 = self._transmit(
                    b'\x00\xc0\x00\x00' + struct.pack('!B', sw2)  # sw2 == le
                )
                response += lres
        except SmartcardException as e:
            self.logger.error('apdu exchange error: %s', e)

        if APDULogging:
            self.logger.debug('response %s %s',
                              '[' + hex((sw1 << 8) + sw2) + ']',
                              b2a_hex(response))

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
            self.logger.debug('control %s', b2a_hex(control_data))

        try:
            response = self.connection.control(
                control_code,
                list(six.iterbytes(control_data))
            )
            response = bytes(bytearray(response))
        except SmartcardException as e:
            self.logger.error('control error: ' + str(e))

        if APDULogging:
            self.logger.debug('response %s', b2a_hex(response))

        return response
