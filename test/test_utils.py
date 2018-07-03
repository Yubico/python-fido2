# coding=utf-8

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


import unittest
from binascii import a2b_hex
from threading import Event

from fido2.utils import (
    Timeout,
    hmac_sha256,
    sha256,
    websafe_encode,
    websafe_decode
)


class TestSha256(unittest.TestCase):

    def test_sha256_vectors(self):
        self.assertEqual(sha256(b'abc'), a2b_hex(b'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'))  # noqa
        self.assertEqual(sha256(b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'), a2b_hex(b'248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'))  # noqa


class TestHmacSha256(unittest.TestCase):

    def test_hmac_sha256_vectors(self):
        self.assertEqual(hmac_sha256(
            b'\x0b'*20,
            b'Hi There'
        ), a2b_hex(b'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'))  # noqa

        self.assertEqual(hmac_sha256(
            b'Jefe',
            b'what do ya want for nothing?'
        ), a2b_hex(b'5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'))  # noqa


class TestWebSafe(unittest.TestCase):
    # Base64 vectors adapted from https://tools.ietf.org/html/rfc4648#section-10

    def test_websafe_decode(self):
        self.assertEqual(websafe_decode(b''), b'')
        self.assertEqual(websafe_decode(b'Zg'), b'f')
        self.assertEqual(websafe_decode(b'Zm8'), b'fo')
        self.assertEqual(websafe_decode(b'Zm9v'), b'foo')
        self.assertEqual(websafe_decode(b'Zm9vYg'), b'foob')
        self.assertEqual(websafe_decode(b'Zm9vYmE'), b'fooba')
        self.assertEqual(websafe_decode(b'Zm9vYmFy'), b'foobar')

    def test_websafe_decode_unicode(self):
        self.assertEqual(websafe_decode(u''), b'')
        self.assertEqual(websafe_decode(u'Zm9vYmFy'), b'foobar')

    def test_websafe_encode(self):
        self.assertEqual(websafe_encode(b''), u'')
        self.assertEqual(websafe_encode(b'f'), u'Zg')
        self.assertEqual(websafe_encode(b'fo'), u'Zm8')
        self.assertEqual(websafe_encode(b'foo'), u'Zm9v')
        self.assertEqual(websafe_encode(b'foob'), u'Zm9vYg')
        self.assertEqual(websafe_encode(b'fooba'), u'Zm9vYmE')
        self.assertEqual(websafe_encode(b'foobar'), u'Zm9vYmFy')


class TestTimeout(unittest.TestCase):

    def test_event(self):
        event = Event()
        timeout = Timeout(event)
        self.assertIsNone(timeout.timer)
        with timeout as e:
            self.assertIs(event, e)
            self.assertFalse(e.is_set())
        self.assertFalse(event.is_set())

    def test_timer_stops(self):
        timeout = Timeout(10)
        self.assertFalse(timeout.timer.is_alive())
        with timeout as e:
            self.assertTrue(timeout.timer.is_alive())
            self.assertFalse(e.is_set())
        self.assertFalse(timeout.timer.is_alive())
        self.assertFalse(e.is_set())

    def test_timer_triggers(self):
        with Timeout(0.01) as e:
            self.assertTrue(e.wait(1.0))
        self.assertTrue(e.is_set())
