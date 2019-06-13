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
from smartcard.System import readers
from binascii import b2a_hex
import struct
import six

logger = logging.getLogger(__name__)


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

    @classmethod
    def list_devices(cls, selector=''):
        """
        Returns list of pcsc readers connected to the system. Iterator.
        :param selector: text selector. select only readers that have it in name
        :return: iterator. next pcsc device.
        """

        for reader in readers():
            if reader.name.find(selector) >= 0:
                yield cls(reader)

        logger.debug('No more devices found.')

    def _transmit(self, apdu, protocol=None):
        resp, sw1, sw2 = self.connection.transmit(list(six.iterbytes(apdu)))
        return bytes(bytearray(resp)), sw1, sw2

    def connect(self):
        """Connect to the reader."""

        self.connection.connect()  # protocol=CardConnection.T0_protocol
        logger.debug('protocol %d', self.connection.getProtocol())

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

        response = b''
        sw1, sw2 = 0, 0

        logger.debug('apdu %s', b2a_hex(apdu))

        response, sw1, sw2 = self._transmit(apdu)

        logger.debug('response %s %s',
                     '[' + hex((sw1 << 8) + sw2) + ']',
                     b2a_hex(response))

        return response, sw1, sw2

    def control_exchange(self, control_code, control_data=b''):
        """
        Sends control sequence to reader's driver
        :param control_data: byte string. data to send to driver
        :param control_code: int. code to send to reader driver.
        :return: byte string. response
        """
        response = b''

        logger.debug('control %s', b2a_hex(control_data))

        response = self.connection.control(
            control_code,
            list(six.iterbytes(control_data))
        )
        response = bytes(bytearray(response))

        logger.debug('response %s', b2a_hex(response))

        return response
