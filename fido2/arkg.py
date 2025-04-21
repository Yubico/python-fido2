# Copyright (c) 2024 Yubico AB
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

from .cose import CoseKey, ESP256
from .utils import bytes2int

from cryptography.hazmat.primitives.hashes import SHA256, Hash, HashAlgorithm
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ecdsa.curves import Curve, NIST256p
from ecdsa.ellipticcurve import Point

from dataclasses import dataclass
from typing import Tuple, Sequence
import struct


def strxor(a: bytes, b: bytes) -> bytes:
    c = bytearray(len(a))
    for i in range(len(a)):
        c[i] = a[i] ^ b[i]
    return c


def ecdh(point: Point, scalar: int) -> bytes:
    enc = (point * scalar).to_bytes("uncompressed")
    ln = len(enc) // 2
    return enc[1 : ln + 1]


@dataclass
class HTF:
    """
    hash_to_field(msg, count)

    Parameters:
    - DST, a domain separation tag (see Section 3.1).
    - F, a finite field of characteristic p and order q = p^m.
    - p, the characteristic of F (see immediately above).
    - m, the extension degree of F, m >= 1 (see immediately above).
    - L = ceil((ceil(log2(p)) + k) / 8), where k is the security
      parameter of the suite (e.g., k = 128).
    - expand_message, a function that expands a byte string and
      domain separation tag into a uniformly random byte string
      (see Section 5.3).
    """

    DST: bytes
    p: int
    # m: int - is always 1
    L: int
    Hash: HashAlgorithm
    # expand_message is always xmd

    def expand_message_xmd(self, msg: bytes, len_in_bytes: int):
        """
        expand_message_xmd(msg, DST, len_in_bytes)

        Parameters:
        - H, a hash function (see requirements above).
        - b_in_bytes, b / 8 for b the output size of H in bits.
          For example, for b = 256, b_in_bytes = 32.
        - s_in_bytes, the input block size of H, measured in bytes (see
          discussion above). For example, for SHA-256, s_in_bytes = 64.

        Input:
        - msg, a byte string.
        - DST, a byte string of at most 255 bytes.
          See below for information on using longer DSTs.
        - len_in_bytes, the length of the requested output in bytes,
          not greater than the lesser of (255 * b_in_bytes) or 2^16-1.

        Output:
        - uniform_bytes, a byte string.

        Steps:
        1.  ell = ceil(len_in_bytes / b_in_bytes)
        2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
        3.  DST_prime = DST || I2OSP(len(DST), 1)
        4.  Z_pad = I2OSP(0, s_in_bytes)
        5.  l_i_b_str = I2OSP(len_in_bytes, 2)
        6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
        7.  b_0 = H(msg_prime)
        8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        9.  for i in (2, ..., ell):
        10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
        11. uniform_bytes = b_1 || ... || b_ell
        12. return substr(uniform_bytes, 0, len_in_bytes)
        """
        b_in_bytes = self.Hash.digest_size

        ell = -(-len_in_bytes // b_in_bytes)
        if ell > 255 or len_in_bytes > 65535 or len(self.DST) > 255:
            raise ValueError("Invalid size of input/output")

        dst_prime = self.DST + struct.pack(">B", len(self.DST))
        z_pad = b"\x00" * self.Hash.block_size
        l_i_b_str = struct.pack(">H", len_in_bytes)
        msg_prime = z_pad + msg + l_i_b_str + b"\x00" + dst_prime
        d = Hash(self.Hash)
        d.update(msg_prime)
        b_0 = d.finalize()
        b_xor = b_0
        uniform_bytes = bytearray()
        for i in range(1, ell + 1):
            d = Hash(self.Hash)
            d.update(b_xor + struct.pack(">B", i) + dst_prime)
            b_i = d.finalize()
            uniform_bytes.extend(b_i)
            b_xor = strxor(b_0, b_i)
        return uniform_bytes[:len_in_bytes]

    def hash_to_field(self, msg: bytes, count: int) -> Sequence[int]:
        """
        hash_to_field(msg, count)

        Input:
        - msg, a byte string containing the message to hash.
        - count, the number of elements of F to output.

        Output:
        - (u_0, ..., u_(count - 1)), a list of field elements.

        Steps:
        1. len_in_bytes = count * m * L
        2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
        3. for i in (0, ..., count - 1):
        4.   for j in (0, ..., m - 1):
        5.     elm_offset = L * (j + i * m)
        6.     tv = substr(uniform_bytes, elm_offset, L)
        7.     e_j = OS2IP(tv) mod p
        8.   u_i = (e_0, ..., e_(m - 1))
        9. return (u_0, ..., u_(count - 1))
        """
        # Only implemented for m = 1
        uniform_bytes = self.expand_message_xmd(msg, count * self.L)
        elements = list()
        for i in range(count):
            offset = self.L * i
            tv = uniform_bytes[offset : offset + self.L]
            e_j = bytes2int(tv) % self.p
            elements.append(e_j)
        return elements


@dataclass
class BL:
    crv: Curve
    Hash: HashAlgorithm
    DST_ext: bytes

    def blind_public_key(self, pk: Point, tau: bytes, ctx: bytes) -> Point:
        """
        BL-Blind-Public-Key(pk, tau, ctx) -> pk_tau

            tau' = hash_to_field(tau, 1) with the parameters:
                DST: 'ARKG-BL-EC.' || DST_ext || ctx
                F: GF(N), the scalar field
                   of the prime order subgroup of crv
                p: N
                m: 1
                L: The L defined in hash-to-crv-suite
                expand_message: The expand_message function
                                defined in hash-to-crv-suite

            pk_tau = pk + tau' * G
        """
        dst = b"ARKG-BL-EC." + self.DST_ext + ctx
        htf = HTF(dst, self.crv.order, 48, self.Hash())

        tau_prime = htf.hash_to_field(tau, 1)[0]

        pk_tau = pk + (tau_prime * self.crv.generator)
        return pk_tau


@dataclass
class KEM:
    crv: Curve
    Hash: HashAlgorithm
    DST_ext: bytes

    def sub_kem_derive_key_pair(self, ikm) -> Tuple[Point, int]:
        """
        Sub-Kem-Derive-Key-Pair(ikm) -> (pk, sk)

            sk = hash_to_field(ikm, 1) with the parameters:
                DST: 'ARKG-KEM-ECDH-KG.' || DST_ext
                F: GF(N), the scalar field
                  of the prime order subgroup of crv
                p: N
                m: 1
                L: The L defined in hash-to-crv-suite
                expand_message: The expand_message function
                                defined in hash-to-crv-suite

            pk = sk * G
        """
        htf = HTF(b"ARKG-KEM-ECDH-KG." + self.DST_ext, self.crv.order, 48, self.Hash())
        sk = htf.hash_to_field(ikm, 1)[0]
        pk = sk * self.crv.generator
        return pk, sk

    def sub_kem_encaps(self, pk: Point, ikm: bytes, ctx: bytes) -> Tuple[bytes, bytes]:
        """
        ECDH(pk, sk) represents the compact output of ECDH [RFC6090]
        using public key (curve point) pk and private key (exponent) sk.

        G is the generator of the prime order subgroup of crv.

        N is the order of G.

        Sub-Kem-Encaps(pk, ikm, ctx) -> (k, c)

            (pk', sk') = Sub-Kem-Derive-Key-Pair(ikm)

            k = ECDH(pk, sk')
            c = Elliptic-Curve-Point-to-Octet-String(pk')
        """
        pk_prime, sk_prime = self.sub_kem_derive_key_pair(ikm)
        k = ecdh(pk, sk_prime)
        c = pk_prime.to_bytes("uncompressed")

        return k, c

    def encaps(self, pk: Point, ikm: bytes, ctx: bytes) -> Tuple[bytes, bytes]:
        """
        KEM-Encaps(pk, ikm, ctx) -> (k, c)

            ctx_sub = 'ARKG-KEM-HMAC.' || DST_ext || ctx
            (k', c') = Sub-Kem-Encaps(pk, ikm, ctx_sub)

            prk = HKDF-Extract with the arguments:
                Hash: Hash
                salt: not set
                IKM: k'

            mk = HKDF-Expand with the arguments:
                Hash: Hash
                PRK: prk
                info: 'ARKG-KEM-HMAC-mac.' || DST_ext || ctx
                L: L
            t = HMAC-Hash-128(K=mk, text=c')

            k = HKDF-Expand with the arguments:
                Hash: Hash
                PRK: prk
                info: 'ARKG-KEM-HMAC-shared.' || DST_ext || ctx
                L: The length of k' in octets.
            c = t || c'
        """

        h = self.Hash()

        ctx_sub = b"ARKG-KEM-HMAC." + self.DST_ext + ctx
        k_prime, c_prime = self.sub_kem_encaps(pk, ikm, ctx_sub)

        mk = HKDF(
            h,
            h.digest_size,
            None,
            b"ARKG-KEM-HMAC-mac." + self.DST_ext + ctx,
        ).derive(k_prime)

        hmac = HMAC(mk, h)
        hmac.update(c_prime)
        t = hmac.finalize()[:16]  # Truncate to 128-bit

        k = HKDF(
            h,
            len(k_prime),
            None,
            b"ARKG-KEM-HMAC-shared." + self.DST_ext + ctx,
        ).derive(k_prime)

        c = t + c_prime

        return k, c


@dataclass
class ARKG:
    """
    ARKG instance parameters:
        BL        A key blinding scheme.
        KEM       A key encapsulation mechanism.
    """

    bl: BL
    kem: KEM

    def derive_public_key(
        self, pk_bl: Point, pk_kem: Point, ikm: bytes, ctx: bytes
    ) -> Tuple[Point, bytes]:
        """
        ARKG-Derive-Public-Key((pk_bl, pk_kem), ikm, ctx) -> (pk', kh)
            ARKG instance parameters:
                BL        A key blinding scheme.
                KEM       A key encapsulation mechanism.

            Inputs:
                pk_bl     A key blinding public key.
                pk_kem    A key encapsulation public key.
                ikm       Input entropy for KEM encapsulation.
                ctx       An octet string of length at most 64,
                            containing optional context and
                            application specific information
                            (can be a zero-length string).

            Output:
                pk'       A blinded public key.
                kh        A key handle for deriving the blinded
                            private key sk' corresponding to pk'.

            The output (pk', kh) is calculated as follows:

            if LEN(ctx) > 64:
                Abort with an error.

            ctx'    = I2OSP(LEN(ctx), 1) || ctx
            ctx_bl  = 'ARKG-Derive-Key-BL.'  || ctx'
            ctx_kem = 'ARKG-Derive-Key-KEM.' || ctx'

            (tau, c) = KEM-Encaps(pk_kem, ikm, ctx_kem)
            pk' = BL-Blind-Public-Key(pk_bl, tau, ctx_bl)

            kh = c
        """
        assert len(ctx) <= 64  # nosec

        ctx_prime = struct.pack(">B", len(ctx)) + ctx
        ctx_bl = b"ARKG-Derive-Key-BL." + ctx_prime
        ctx_kem = b"ARKG-Derive-Key-KEM." + ctx_prime

        tau, c = self.kem.encaps(pk_kem, ikm, ctx_kem)
        pk_prime = self.bl.blind_public_key(pk_bl, tau, ctx_bl)

        kh = c

        return pk_prime, kh


def _cose2point(cose):
    return Point(NIST256p.curve, bytes2int(cose[-2]), bytes2int(cose[-3]))


ARKG_P256_ESP256 = -65539


class ARKG_P256_DERIVED(ESP256):
    def __init__(self, *args, parent_kid: bytes, kh: bytes, ctx: bytes, **kwargs):
        super().__init__(*args, **kwargs)
        self._parent_kid = parent_kid
        self._kh = kh
        self._ctx = ctx

    def get_ref(self):
        return {
            1: -65538,  # kty: Ref-ARKG-derived
            2: self._parent_kid,
            3: ARKG_P256_ESP256,  # alg: ESP256 with key derived by ARKG-P256
            -1: self._kh,
            -2: self._ctx,
            -3: ARKG_P256.ALGORITHM,
        }


class ARKG_P256(CoseKey):
    """
    The identifier ARKG-P256 represents the following ARKG instance:

        BL: Elliptic curve addition as described in Section 3.1 with the parameters:

            crv: The NIST curve secp256r1 [SEC2].

            hash-to-crv-suite: P256_XMD:SHA-256_SSWU_RO_ [RFC9380].

            DST_ext: 'ARKG-P256'.

        KEM: ECDH as described in Section 3.3 with the parameters:

            crv: The NIST curve secp256r1 [SEC2].

            Hash: SHA-256 [FIPS 180-4].

            hash-to-crv-suite: P256_XMD:SHA-256_SSWU_RO_ [RFC9380].

            DST_ext: 'ARKG-P256'.
    """

    ALGORITHM = -65700
    _ARKG = ARKG(
        bl=BL(crv=NIST256p, Hash=SHA256, DST_ext=b"ARKG-P256"),
        kem=KEM(crv=NIST256p, Hash=SHA256, DST_ext=b"ARKG-ECDH.ARKG-P256"),
    )

    @property
    def pkbl(self) -> CoseKey:
        return CoseKey.parse(self[-1])

    @property
    def pkkem(self) -> CoseKey:
        return CoseKey.parse(self[-2])

    def derive_public_key(self, ikm: bytes, ctx: bytes) -> CoseKey:
        point, kh = self._ARKG.derive_public_key(
            _cose2point(self.pkbl),
            _cose2point(self.pkkem),
            ikm,
            ctx,
        )
        point_enc = point.to_bytes("uncompressed")
        ln = len(point_enc) // 2
        return ARKG_P256_DERIVED(
            {
                1: 2,  # kty: EC
                3: self[-3],  # derived key alg (-9)
                -1: 1,
                -2: point_enc[1 : ln + 1],  # x-coordinate
                -3: point_enc[1 + ln :],  # y-coordinate
            },
            parent_kid=self[2],
            kh=kh,
            ctx=ctx,
        )
