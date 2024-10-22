from .cose import CoseKey
from .utils import int2bytes, bytes2int
from . import cbor

from cryptography.hazmat.primitives.hashes import SHA256, Hash, HashAlgorithm
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from fastecdsa.curve import Curve, P256
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa.point import Point
import fastecdsa.keys

from dataclasses import dataclass
from typing import Tuple, Sequence
import struct


def strxor(a: bytes, b: bytes) -> bytes:
    c = bytearray(len(a))
    for i in range(len(a)):
        c[i] = a[i] ^ b[i]
    return c


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

    def blind_public_key(self, pk: Point, tau: bytes, info: bytes) -> Point:
        """
        BL-Blind-Public-Key(pk, tau, info) -> pk_tau

            tau' = hash_to_field(tau, 1) with the parameters:
                DST: 'ARKG-BL-EC.' || DST_ext || info
                F: GF(N), the scalar field
                   of the prime order subgroup of crv
                p: N
                m: 1
                L: The L defined in hash-to-crv-suite
                expand_message: The expand_message function
                                defined in hash-to-crv-suite

            pk_tau = pk + tau' * G
        """
        dst = b"ARKG-BL-EC." + self.DST_ext + info
        htf = HTF(dst, self.crv.q, 48, self.Hash())

        tau_prime = htf.hash_to_field(tau, 1)[0]

        pk_tau = pk + (tau_prime * self.crv.G)
        return pk_tau


@dataclass
class KEM:
    crv: Curve
    Hash: HashAlgorithm
    DST_ext: bytes

    def sub_kem_generate(self) -> Tuple[int, Point]:
        """
        Sub-Kem-Generate-Keypair() -> (pk, sk)

            Generate (pk, sk) using some procedure defined for crv.
        """
        sk, pk = fastecdsa.keys.gen_keypair(self.crv)
        return pk, sk

    def sub_kem_encaps(self, pk: Point, info: bytes) -> Tuple[bytes, bytes]:
        """
        ECDH(pk, sk) represents the compact output of ECDH [RFC6090]
        using public key (curve point) pk and private key (exponent) sk.

        G is the generator of the prime order subgroup of crv.

        N is the order of G.

        Sub-Kem-Encaps(pk, info) -> (k, c)

            (pk', sk') = Sub-Kem-Generate-Keypair()

            k = ECDH(pk, sk')
            c = Elliptic-Curve-Point-to-Octet-String(pk')
        """
        pk_prime, sk_prime = self.sub_kem_generate()
        # TODO: Don't hardcode length
        k = int2bytes((pk * sk_prime).x, 32)
        c = SEC1Encoder().encode_public_key(pk_prime, compressed=False)

        return k, c

    def encaps(self, pk: Point, info: bytes) -> Tuple[bytes, bytes]:
        """
        KEM-Encaps(pk, info) -> (k, c)

            info_sub = 'ARKG-KEM-HMAC.' || DST_ext || info
            (k', c') = Sub-Kem-Encaps(pk, info_sub)

            prk = HKDF-Extract with the arguments:
                Hash: Hash
                salt: not set
                IKM: k'

            mk = HKDF-Expand with the arguments:
                Hash: Hash
                PRK: prk
                info: 'ARKG-KEM-HMAC-mac.' || DST_ext || info
                L: L
            t = HMAC-Hash-128(K=mk, text=c')

            k = HKDF-Expand with the arguments:
                Hash: Hash
                PRK: prk
                info: 'ARKG-KEM-HMAC-shared.' || DST_ext || info
                L: The length of k' in octets.
            c = t || c'
        """

        dst_ext = self.DST_ext
        h = self.Hash()

        info_sub = b"ARKG-KEM-HMAC." + dst_ext + info
        k_prime, c_prime = self.sub_kem_encaps(pk, info_sub)

        mk = HKDF(
            h,
            h.digest_size,
            None,
            b"ARKG-KEM-HMAC-mac." + dst_ext + info,
        ).derive(k_prime)

        hmac = HMAC(mk, h)
        hmac.update(c_prime)
        t = hmac.finalize()[:16]  # Truncate to 128-bit

        k = HKDF(
            h,
            len(k_prime),
            None,
            b"ARKG-KEM-HMAC-shared." + dst_ext + info,
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
        self, pk_kem: Point, pk_bl: Point, info: bytes
    ) -> Tuple[Point, bytes]:
        """
        ARKG-Derive-Public-Key((pk_kem, pk_bl), info) -> (pk', kh)
            Inputs:
                pk_kem    A key encapsulation public key.
                pk_bl     A key blinding public key.
                info      An octet string containing optional context
                            and application specific information
                            (can be a zero-length string).

            Output:
                pk'       A blinded public key.
                kh        A key handle for deriving the blinded
                            private key sk' corresponding to pk'.

            The output (pk', kh) is calculated as follows:

            info_kem = 'ARKG-Derive-Key-KEM.' || info
            info_bl  = 'ARKG-Derive-Key-BL.'  || info

            (tau, c) = KEM-Encaps(pk_kem, info_kem)
            pk' = BL-Blind-Public-Key(pk_bl, tau, info_bl)

            kh = c
        """
        info_kem = b"ARKG-Derive-Key-KEM." + info
        info_bl = b"ARKG-Derive-Key-BL." + info

        tau, c = self.kem.encaps(pk_kem, info_kem)
        pk_prime = self.bl.blind_public_key(pk_bl, tau, info_bl)

        kh = c

        return pk_prime, kh


"""
The identifier ARKG-P256ADD-ECDH represents the following ARKG instance:

    BL: Elliptic curve addition as described in Section 3.1 with the parameters:

        crv: The NIST curve secp256r1 [SEC2].

        hash-to-crv-suite: P256_XMD:SHA-256_SSWU_RO_ [RFC9380].

        DST_ext: 'ARKG-P256ADD-ECDH'.

    KEM: ECDH as described in Section 3.3 with the parameters:

        crv: The NIST curve secp256r1 [SEC2].

        Hash: SHA-256 [FIPS 180-4].

        DST_ext: 'ARKG-P256ADD-ECDH'.
"""


def _cose2point(cose):
    return SEC1Encoder.decode_public_key(b"\x04" + cose[-2] + cose[-3], P256)


class ARKG_P256ADD_ECDH(CoseKey):
    ALGORITHM = -65539
    _HASH_ALG = SHA256()
    _ARKG = ARKG(
        bl=BL(crv=P256, Hash=SHA256, DST_ext=b"ARKG-P256ADD-ECDH"),
        kem=KEM(crv=P256, Hash=SHA256, DST_ext=b"ARKG-P256ADD-ECDH"),
    )

    @property
    def blinding_key(self) -> CoseKey:
        return CoseKey.parse(self[-1])

    @property
    def kem_key(self) -> CoseKey:
        return CoseKey.parse(self[-2])

    def derive_public_key(self, info: bytes) -> Tuple[CoseKey, bytes]:
        point, kh = self._ARKG.derive_public_key(
            _cose2point(self.kem_key),
            _cose2point(self.blinding_key),
            info,
        )
        pk = CoseKey.parse(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: int2bytes(point.x, 32),
                -3: int2bytes(point.y, 32),
            }
        )

        # Return the complete COSE key ref used as key handle to getAssertion
        ref = dict(self.get_key_handle())
        ref.update(
            {
                1: -65538,  # kty: Ref-ARKG-derived
                -1: kh,
                -2: info,
            }
        )

        ref_kh = cbor.encode(ref)

        return pk, ref_kh
