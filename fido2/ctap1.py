# Copyright (c) 2013 Yubico AB
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

from .hid import CTAPHID
from .utils import websafe_encode, websafe_decode, bytes2int
from .cose import ES256
from .attestation import FidoU2FAttestation
from enum import IntEnum, unique
from binascii import b2a_hex
import struct
import six


@unique
class APDU(IntEnum):
    OK = 0x9000
    USE_NOT_SATISFIED = 0x6985
    WRONG_DATA = 0x6a80


class ApduError(Exception):
    def __init__(self, code, data=b''):
        self.code = code
        self.data = data

    def __repr__(self):
        return 'APDU error: 0x{:04X} {:d} bytes of data'.format(
            self.code, len(self.data))


class RegistrationData(bytes):
    def __init__(self, _):
        if six.indexbytes(self, 0) != 0x05:
            raise ValueError('Reserved byte != 0x05')

        self.public_key = self[1:66]
        kh_len = six.indexbytes(self, 66)
        self.key_handle = self[67:67+kh_len]

        cert_offs = 67 + kh_len
        cert_len = six.indexbytes(self, cert_offs + 1)
        if cert_len > 0x80:
            n_bytes = cert_len - 0x80
            cert_len = bytes2int(self[cert_offs+2:cert_offs+2+n_bytes]) \
                + n_bytes
        cert_len += 2
        self.certificate = self[cert_offs:cert_offs+cert_len]
        self.signature = self[cert_offs+cert_len:]

    @property
    def b64(self):
        return websafe_encode(self)

    def verify(self, app_param, client_param):
        FidoU2FAttestation.verify_signature(
            app_param, client_param, self.key_handle, self.public_key,
            self.certificate, self.signature)

    def __repr__(self):
        return ("RegistrationData(public_key: h'%s', key_handle: h'%s', "
                "certificate: h'%s', signature: h'%s')") % (
                    b2a_hex(x).decode() for x in (
                        self.public_key,
                        self.key_handle,
                        self.certificate,
                        self.signature
                    )
                )

    def __str__(self):
        return '%r' % self

    @classmethod
    def from_b64(cls, data):
        return cls(websafe_decode(data))


class SignatureData(bytes):
    def __init__(self, _):
        self.user_presence, self.counter = struct.unpack('>BI', self[:5])
        self.signature = self[5:]

    @property
    def b64(self):
        return websafe_encode(self)

    def verify(self, app_param, client_param, public_key):
        m = app_param + self[:5] + client_param
        ES256.from_ctap1(public_key).verify(m, self.signature)

    def __repr__(self):
        return ('SignatureData(user_presence: 0x%02x, counter: %d, '
                "signature: h'%s'") % (self.user_presence, self.counter,
                                       b2a_hex(self.signature))

    def __str__(self):
        return '%r' % self

    @classmethod
    def from_b64(cls, data):
        return cls(websafe_decode(data))


class CTAP1(object):
    @unique
    class INS(IntEnum):
        REGISTER = 0x01
        AUTHENTICATE = 0x02
        VERSION = 0x03

    def __init__(self, device):
        self.device = device

    def send_apdu(self, cla=0, ins=0, p1=0, p2=0, data=b''):
        size = len(data)
        size_h = size >> 16 & 0xff
        size_l = size & 0xffff
        apdu = struct.pack('>BBBBBH', cla, ins, p1, p2, size_h, size_l) \
            + data + b'\0\0'

        response = self.device.call(CTAPHID.MSG, apdu)
        status = struct.unpack('>H', response[-2:])[0]
        data = response[:-2]
        if status != APDU.OK:
            raise ApduError(status, data)
        return data

    def get_version(self):
        return self.send_apdu(ins=CTAP1.INS.VERSION).decode()

    def register(self, client_param, app_param):
        data = client_param + app_param
        response = self.send_apdu(ins=CTAP1.INS.REGISTER, data=data)
        return RegistrationData(response)

    def authenticate(self, client_param, app_param, key_handle,
                     check_only=False):
        data = client_param + app_param \
            + struct.pack('>B', len(key_handle)) + key_handle
        p1 = 0x07 if check_only else 0x03
        response = self.send_apdu(ins=CTAP1.INS.AUTHENTICATE, p1=p1, data=data)
        return SignatureData(response)
