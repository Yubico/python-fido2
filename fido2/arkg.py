from .cose import CoseKey

from cryptography.hazmat.primitives.hashes import SHA256, Hash, HashAlgorithm
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from fastecdsa.curve import Curve, P256
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa.point import Point
import fastecdsa.keys

from dataclasses import dataclass
from typing import Tuple
import struct


def strxor(a, b):
    c = bytearray(len(a))
    for i in range(len(a)):
        c[i] = a[i] ^ b[i]
    return c


def expand_message_xmd(H, msg, dst, out_len):
    ell = -(-out_len // H.digest_size)
    dst_prime = dst + struct.pack(">B", len(dst))
    z_pad = b"\x00" * H.block_size
    l_i_b_str = struct.pack(">H", out_len)
    msg_prime = z_pad + msg + l_i_b_str + b"\x00" + dst_prime
    d = Hash(H)
    d.update(msg_prime)
    b_0 = d.finalize()
    b_xor = b_0
    uniform_bytes = bytearray()
    for i in range(1, ell + 1):
        d = Hash(H)
        d.update(b_xor + struct.pack(">B", i) + dst_prime)
        b_i = d.finalize()
        uniform_bytes.extend(b_i)
        b_xor = strxor(b_0, b_i)
    return uniform_bytes[:out_len]


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


# m is always 1
def hash_to_field(msg, count, dst, p, L, H):
    elements = list()
    uniform_bytes = expand_message_xmd(H, msg, dst, count * L)
    for i in range(count):
        offset = L * i
        tv = uniform_bytes[offset : offset + L]
        e_j = int.from_bytes(tv) % p
        elements.append(e_j)
    return elements


@dataclass
class HTF:
    DST: bytes
    p: int
    # m: int - is always 1
    L: int
    Hash: HashAlgorithm

    def expand_message_xmd(self, msg, out_len):
        ell = -(-out_len // self.Hash.digest_size)
        dst_prime = self.DST + struct.pack(">B", len(self.DST))
        z_pad = b"\x00" * self.Hash.block_size
        l_i_b_str = struct.pack(">H", out_len)
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
        return uniform_bytes[:out_len]

    def hash_to_field(self, msg, count):
        elements = list()
        uniform_bytes = self.expand_message_xmd(msg, count * self.L)
        for i in range(count):
            offset = self.L * i
            tv = uniform_bytes[offset : offset + self.L]
            e_j = int.from_bytes(tv) % self.p
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
        tau_p = htf.hash_to_field(tau, 1)[0]

        pk_tau = pk + (tau_p * self.crv.G)
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
        k = int.to_bytes((pk * sk_prime).x, 32)
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

        mk = HKDF(h, 32, None, b"ARKG-KEM-HMAC-mac." + dst_ext + info).derive(k_prime)

        hmac = HMAC(mk, h)
        hmac.update(c_prime)
        t = hmac.finalize()[:16]

        k = HKDF(h, 32, None, b"ARKG-KEM-HMAC-shared." + dst_ext + info).derive(k_prime)

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
arkg_p256_ecdh = ARKG(
    bl=BL(crv=P256, Hash=SHA256, DST_ext=b"ARKG-P256ADD-ECDH"),
    kem=KEM(crv=P256, Hash=SHA256, DST_ext=b"ARKG-P256ADD-ECDH"),
)


def _cose2point(cose):
    return SEC1Encoder.decode_public_key(b"\x04" + cose[-2] + cose[-3], P256)


class ARKG_P256ADD_ECDH(CoseKey):
    ALGORITHM = -65539
    _HASH_ALG = SHA256()

    @property
    def blinding_key(self) -> CoseKey:
        return CoseKey.parse(self[-1])

    @property
    def kem_key(self) -> CoseKey:
        return CoseKey.parse(self[-2])

    def derive_public_key(self, info: bytes) -> Tuple[CoseKey, bytes]:
        point, kh = arkg_p256_ecdh.derive_public_key(
            _cose2point(self.blinding_key),
            _cose2point(self.kem_key),
            info,
        )
        pk = CoseKey.parse(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: int.to_bytes(point.x, 32),
                -3: int.to_bytes(point.y, 32),
            }
        )
        return pk, kh
