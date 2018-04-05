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

from base64 import urlsafe_b64decode, urlsafe_b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac, hashes
from threading import Timer, Event
from binascii import b2a_hex
import six
import numbers

__all__ = [
    'Timeout',
    'websafe_encode',
    'websafe_decode',
    'sha256',
    'hmac_sha256',
    'bytes2int',
    'int2bytes'
]


def sha256(data):
    h = hashes.Hash(hashes.SHA256(), default_backend())
    h.update(data)
    return h.finalize()


def hmac_sha256(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), default_backend())
    h.update(data)
    return h.finalize()


def bytes2int(value):
    return int(b2a_hex(value), 16)


def int2bytes(value, minlen=-1):
    ba = []
    while value > 0xff:
        ba.append(0xff & value)
        value >>= 8
    ba.append(value)
    ba.extend([0]*(minlen - len(ba)))
    return bytes(bytearray(reversed(ba)))


def websafe_decode(data):
    if isinstance(data, six.text_type):
        data = data.encode('ascii')
    data += b'=' * (-len(data) % 4)
    return urlsafe_b64decode(data)


def websafe_encode(data):
    if isinstance(data, six.text_type):
        data = data.encode('ascii')
    return urlsafe_b64encode(data).replace(b'=', b'').decode('ascii')


class Timeout(object):
    def __init__(self, time_or_event):
        if isinstance(time_or_event, numbers.Number):
            self.event = Event()
            self.timer = Timer(time_or_event, self.event.set)
        else:
            self.event = time_or_event
            self.timer = None

    def __enter__(self):
        if self.timer:
            self.timer.start()
        return self.event

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.timer:
            self.timer.cancel()
            self.timer.join()
