# ruff: noqa: S101

import math
import os
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature

from . import cbor
from .utils import sha256


def modpow(base, exp, modulus):
    result = 1
    base %= modulus

    while exp > 0:
        if (exp & 1) == 1:
            result = (result * base) % modulus
        exp >>= 1
        base = (base * base) % modulus

    return result


def modinv(n, primeModulus):
    return modpow(n, primeModulus - 2, primeModulus)


def modsqrt(n, primeModulus):
    assert (primeModulus % 4) == 3
    s = modpow(n, (primeModulus + 1) // 4, primeModulus)
    if s != 0 and s != 1 and modpow(s, 2, primeModulus) == n:
        return s
    else:
        return None


class Curve:
    def __init__(self, p, a, b, n, h, coord_len, scalar_len, generator):
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.h = h
        self.coord_len = coord_len
        self.scalar_len = scalar_len
        (gx, gy) = generator
        self.generator = PointAffine(gx, gy, self).to_projective()

    def zero(self):
        return PointAffine(0, 0, self).zero().to_projective()

    def pow(self, b, e):
        return modpow(b, e, self.p)

    def sqrt(self, a):
        return modsqrt(a, self.p)

    def find_y(self, x):
        y = self.sqrt(self.pow(x, 3) + self.a * x + self.b)
        if y is not None:
            if self.p - y < y:
                return self.p - y
            else:
                return y

    def insecure_random_scalar(self):
        return int.from_bytes(os.urandom(self.scalar_len * 2), "big") % self.n

    def insecure_random_point(self):
        return self.generator * self.insecure_random_scalar()

    def find_bls_generator(self):
        for x in range(0, 100):
            y = self.find_y(x)
            if y is not None:
                g = PointAffine(x, y, self) * self.h
                if g.is_valid_nonzero():
                    return g.to_projective()

    def scalar_to_big_endian(self, x):
        return int.to_bytes(x, self.scalar_len, "big")

    def point_from_cose(self, cose):
        assert cose[1] == 2  # kty: EC2
        assert cose[-1] == -65601  # crv: BLS12-381 (placeholder value)
        assert len(cose[-2]) == self.coord_len
        assert len(cose[-3]) == self.coord_len
        x = int.from_bytes(cose[-2], "big")
        y = int.from_bytes(cose[-3], "big")
        return PointAffine(x, y, self).to_projective()

    def point_from_sec1_uncompressed(self, sec1: bytes):
        assert sec1[0] == 0x04
        x = int.from_bytes(sec1[1 : (1 + self.coord_len)], "big")
        y = int.from_bytes(sec1[(1 + self.coord_len) : (1 + self.coord_len * 2)], "big")
        return PointAffine(x, y, self).to_projective()


class PointAffine:
    def __init__(self, x, y, crv, is_zero=False):
        self.is_zero = is_zero
        self.x = x
        self.y = y
        self.crv = crv

    def __eq__(self, o):
        assert isinstance(o, PointAffine) or isinstance(o, PointProjective), (
            f"self: {self}, o: {o}"
        )
        assert self.crv is o.crv
        if isinstance(o, PointProjective):
            return self.to_projective() == o
        if self.is_zero and o.is_zero:
            return True
        elif self.is_zero != o.is_zero:
            return False
        else:
            return self.x == o.x and self.y == o.y

    def __repr__(self):
        if self.is_zero:
            return "(ZERO)"
        else:
            L = math.ceil(math.log2(self.crv.p) / 8)
            x = int.to_bytes(self.x, L, "big").hex()
            y = int.to_bytes(self.y, L, "big").hex()
            return f"(0x{x}, 0x{y})"

    def zero(self):
        return PointAffine(0, 0, self.crv, is_zero=True)

    def to_projective(self):
        q = PointProjective(self.x, self.y, 1, self.crv)
        if self.is_zero:
            return q.zero()
        else:
            return q

    def coordinate_to_big_endian(self, x):
        return int.to_bytes(x, self.crv.coord_len, "big")

    def to_big_endian_coordinates(self):
        return (
            self.coordinate_to_big_endian(self.x),
            self.coordinate_to_big_endian(self.y),
        )

    def to_sec1_uncompressed(self):
        x, y = self.to_big_endian_coordinates()
        return bytes([0x04]) + x + y

    def is_valid_nonzero(self):
        return (
            not self.is_zero
            and self.crv.pow(self.y, 2)
            == (self.crv.pow(self.x, 3) + self.crv.a * self.x + self.crv.b) % self.crv.p
        )

    def __neg__(self):
        return PointAffine(
            self.x, (-self.y) % self.crv.p, self.crv, is_zero=self.is_zero
        )

    def __add__(self, q):
        assert isinstance(q, PointAffine), f"p: {self}, q: {q}"
        assert self.crv is q.crv
        p = self

        if self.is_zero:
            return q

        elif q.is_zero:
            return p

        else:
            if p.x == q.x:
                if p.y == (-q.y % self.crv.p):
                    return self.zero()
                else:
                    kn = 3 * p.x**2 + self.crv.a
                    kd = 2 * p.y
                    k = kn * modinv(kd, self.crv.p)
            else:
                kn = q.y - p.y
                kd = q.x - p.x
                k = kn * modinv(kd, self.crv.p)

            xr = (k**2 - p.x - q.x) % self.crv.p
            yr = (k * (p.x - xr) - p.y) % self.crv.p
            return PointAffine(xr, yr, self.crv)

    def __mul__(self, k):
        k = k % self.crv.n
        pPow2 = self
        result = self.zero()

        while k > 0:
            if k % 2 != 0:
                result += pPow2
            pPow2 += pPow2
            k >>= 1

        return result


class PointProjective:
    def __init__(self, x, y, z, crv):
        self.x = x
        self.y = y
        self.z = z
        self.crv = crv

    def __eq__(self, o):
        assert isinstance(o, PointProjective) or isinstance(o, PointAffine)
        assert self.crv is o.crv
        if isinstance(o, PointAffine):
            return self == o.to_projective()
        if self.is_zero() and o.is_zero():
            return True
        elif (self.is_zero()) != (o.is_zero()):
            return False
        else:
            return ((self.x * o.z) % self.crv.p == (o.x * self.z) % self.crv.p) and (
                (self.y * o.z) % self.crv.p == (o.y * self.z) % self.crv.p
            )

    def __repr__(self):
        if self.is_zero():
            return "(ZERO)"
        else:
            L = math.ceil(math.log2(self.crv.p) / 8)
            x = int.to_bytes(self.x, L, "big").hex()
            y = int.to_bytes(self.y, L, "big").hex()
            z = int.to_bytes(self.z, L, "big").hex()
            return f"P(0x{x}, 0x{y}, 0x{z})"

    def zero(self):
        return PointProjective(0, 1, 0, self.crv)

    def to_affine(self):
        zinv = modinv(self.z, self.crv.p)
        return PointAffine(
            (self.x * zinv) % self.crv.p, (self.y * zinv) % self.crv.p, self.crv
        )

    def is_zero(self):
        return self.z == 0

    def is_valid_nonzero(self):
        if self.is_zero():
            return False
        else:
            z2 = self.crv.pow(self.z, 2)
            z3 = self.crv.pow(self.z, 3)
            lhs = self.crv.pow(self.y, 2) * self.z
            rhs = self.crv.pow(self.x, 3) + self.crv.a * self.x * z2 + self.crv.b * z3
            return (lhs % self.crv.p) == (rhs % self.crv.p)

    def __neg__(self):
        return PointProjective(self.x, (-self.y) % self.crv.p, self.z, self.crv)

    def __add__(self, q):
        assert isinstance(q, PointProjective)
        assert self.crv is q.crv
        p = self

        if self.is_zero():
            return q

        elif q.is_zero():
            return p

        else:
            if p.x * q.z == q.x * p.z:
                if p.y * q.z == ((-q.y * p.z) % self.crv.p):
                    return self.zero()
                else:
                    yp2 = self.crv.pow(p.y, 2)
                    zp2 = self.crv.pow(p.z, 2)
                    k = (3 * self.crv.pow(p.x, 2) + self.crv.a * zp2) % self.crv.p
                    zr1 = (4 * zp2 * yp2) % self.crv.p
                    xr1 = (self.crv.pow(k, 2) - 8 * p.x * yp2 * p.z) % self.crv.p
                    yr = (2 * p.y) * k * (
                        p.x * zr1 - xr1 * p.z
                    ) - 4 * p.z * zr1 * self.crv.pow(p.y, 3)
                    yr = yr % self.crv.p

                    zr2 = 4 * zp2 * yp2
                    zr = (zr1 * zr2) % self.crv.p
                    xr = (xr1 * zr2) % self.crv.p
                    return PointProjective(xr, yr, zr, self.crv)
            else:
                pxqz = p.x * q.z
                pyqz = p.y * q.z
                qypz = q.y * p.z
                qxpz = q.x * p.z
                pzqz = p.z * q.z
                xpzqmxqzp = pxqz - qxpz
                xpzqmxqzp2 = self.crv.pow(xpzqmxqzp, 2)
                ypzqmyqzp = (pyqz - qypz) % self.crv.p
                ypzqmyqzp2 = self.crv.pow(ypzqmyqzp, 2)
                pzqz_xpzqmxqzp2 = pzqz * xpzqmxqzp2
                k = (pzqz * ypzqmyqzp2 - xpzqmxqzp2 * (pxqz + qxpz)) % self.crv.p
                xr = (xpzqmxqzp * k) % self.crv.p
                yr = (
                    pzqz_xpzqmxqzp2 * (q.x * p.y - p.x * q.y) - ypzqmyqzp * k
                ) % self.crv.p
                zr = (pzqz_xpzqmxqzp2 * xpzqmxqzp) % self.crv.p
                return PointProjective(xr, yr, zr, self.crv)

    def __mul__(self, k):
        k = k % self.crv.n
        pPow2 = self
        result = self.zero()

        while k > 0:
            if k % 2 != 0:
                result += pPow2
            pPow2 += pPow2
            k >>= 1

        return result

    def to_sec1_uncompressed(self):
        return self.to_affine().to_sec1_uncompressed()

    def verify_ecsdsa_sha256(self, signature: bytes, message: bytes):
        assert len(signature) == self.crv.scalar_len * 2
        s = int.from_bytes(signature[: self.crv.scalar_len], "big")
        e = int.from_bytes(signature[self.crv.scalar_len :], "big")
        rv = self.crv.generator * s + self * e
        rv_bin = rv.to_affine().to_sec1_uncompressed()
        ev_bin = sha256(rv_bin + message)
        ev = int.from_bytes(ev_bin, "big") % self.crv.n
        if ev == e:
            return
        raise InvalidSignature()

    def verify_ecsdsa_sha256_split_bbs(
        self, signature: bytes, message: bytes, t2prime: Optional[Any]
    ):
        """Verification of device binding signature based on "Split BBS"
        proposal by Cordian Daniluk and Anja Lehmann"""
        assert len(signature) == self.crv.scalar_len * 3
        if t2prime is None:
            t2prime = self.crv.generator * 0
        s = int.from_bytes(signature[: self.crv.scalar_len], "big")
        c = signature[self.crv.scalar_len : self.crv.scalar_len * 2]
        c_int = int.from_bytes(c, "big") % self.crv.n
        n = signature[self.crv.scalar_len * 2 :]
        t_dsk = self.crv.generator * s + self * c_int
        t2 = t_dsk + t2prime
        t2_bin = t2.to_sec1_uncompressed()
        cv = sha256(n + t2_bin + message)
        cv_int = int.from_bytes(cv, "big") % self.crv.n
        if cv_int == c_int:
            return
        raise InvalidSignature()


def split_bbs_sign(
    crv: Curve,
    sk: int,
    dpk: PointProjective,
    attrs: list[int],
    attr_generators: list[PointProjective],
) -> tuple[PointProjective, int]:
    g1 = crv.generator
    e = crv.insecure_random_scalar()
    A = (
        g1 + dpk + sum((hi * ai for hi, ai in zip(attr_generators, attrs)), crv.zero())
    ) * modinv((e + sk) % crv.n, crv.n)
    if A.is_zero():
        raise ValueError("A was zero")
    return A, e


def begin_split_bbs_proof(
    A: PointProjective,
    e: int,
    dpk: PointProjective,
    attrs: list[int],
    attr_generators: list[PointProjective],
    pk: PointProjective,
    disclose_idx: set[int],
    ctx: bytes,
):
    """First part of "Split BBS.ZKProve" based on proposal by Cordian Daniluk
    and Anja Lehmann"""
    assert len(attrs) == len(attr_generators)
    assert all(d >= 0 and d < len(attrs) for d in disclose_idx)
    assert 0 not in disclose_idx

    crv = CRV_BLS
    g1 = crv.generator
    idx = list(range(len(attrs)))
    undisclosed_idx = set(idx) - disclose_idx
    undisclosed_idx_nonzero = undisclosed_idx - set([0])

    r1 = crv.insecure_random_scalar()
    r2 = crv.insecure_random_scalar()
    r2inv = modinv(r2, crv.n)
    Abar = A * (r1 * r2inv)
    D = (
        g1
        + dpk
        + sum((hi * ai for hi, ai in zip(attr_generators[1:], attrs[1:])), crv.zero())
    ) * r2inv
    Bbar = (D * r1) + (Abar * (-e))
    rr1 = crv.insecure_random_scalar()
    rr2 = crv.insecure_random_scalar()
    re = crv.insecure_random_scalar()
    rai = [
        crv.insecure_random_scalar() if i in undisclosed_idx_nonzero else None
        for i in idx
    ]
    t1 = (D * rr1) + (Abar * re)
    t2prime = D * rr2 + sum(
        (attr_generators[i] * rai[i] for i in undisclosed_idx_nonzero), crv.zero()
    )
    c_host = sha256(
        cbor.encode(
            [
                Abar.to_sec1_uncompressed(),
                Bbar.to_sec1_uncompressed(),
                D.to_sec1_uncompressed(),
                g1.to_sec1_uncompressed(),
                g1.to_sec1_uncompressed(),
                [gen.to_sec1_uncompressed() for gen in attr_generators],
                len(attr_generators) + 1,
                t1.to_sec1_uncompressed(),
                [crv.scalar_to_big_endian(attrs[i]) for i in sorted(disclose_idx)],
                sorted(disclose_idx),
                pk.to_sec1_uncompressed(),
            ]
        )
    )

    return (
        c_host,
        rr1,
        r1,
        rr2,
        r2,
        re,
        e,
        rai,
        attrs,
        disclose_idx,
        Abar,
        Bbar,
        D,
        t2prime,
        dpk,
    )


def finish_split_bbs_proof(
    c_host: bytes,
    rr1: int,
    r1: int,
    rr2: int,
    r2: int,
    re: int,
    e: int,
    rai: list[int],
    attrs: list[int],
    disclose_idx: set[int],
    Abar: PointProjective,
    Bbar: PointProjective,
    D: PointProjective,
    sa0: int,
    c: bytes,
    n: bytes,
    t2prime: PointProjective,
    dpk: PointProjective,
):
    """Second part of "Split BBS.ZKProve" based on proposal by Cordian Daniluk
    and Anja Lehmann"""
    assert len(attrs) == len(rai)
    assert 0 not in disclose_idx

    crv = CRV_BLS
    g1 = crv.generator
    idx = list(range(len(attrs)))
    undisclosed_idx = set(range(len(attrs))) - disclose_idx
    undisclosed_idx_nonzero = undisclosed_idx - set([0])

    c_int = int.from_bytes(c, "big") % crv.n
    t_dsk = g1 * sa0 + dpk * c_int
    t2 = t_dsk + t2prime
    t2_bin = t2.to_sec1_uncompressed()
    c2 = int.from_bytes(sha256(n + t2_bin + c_host), "big") % crv.n
    assert c2 == c_int

    sr1 = (rr1 + c_int * r1) % crv.n
    sr2 = (rr2 + c_int * r2) % crv.n
    se = (re - c_int * e) % crv.n
    sai = [
        sa0,
        *[
            rai[i] - c_int * attrs[i] if i in undisclosed_idx_nonzero else None
            for i in idx[1:]
        ],
    ]

    return Abar, Bbar, D, c_int, sr1, sr2, se, sai, n


def verify_split_bbs_proof(
    Abar: PointProjective,
    Bbar: PointProjective,
    D: PointProjective,
    c: int,
    sr1: int,
    sr2: int,
    se: int,
    sai: list[int],
    pk: PointProjective,
    disclosed_idx: set[int],
    attrs: list[int | None],
    attr_generators: list[PointProjective],
    ctx: bytes,
    n: bytes,
):
    assert len(attrs) == len(attr_generators)
    assert len(sai) == len(attr_generators)
    assert all(d >= 0 and d < len(attr_generators) for d in disclosed_idx)

    crv = CRV_BLS
    g1 = crv.generator
    undisclosed_idx = set(range(len(attr_generators))) - disclosed_idx

    t1 = D * sr1 + Abar * se + Bbar * (-c)
    t2 = (
        D * sr2
        + sum((attr_generators[i] * sai[i] for i in undisclosed_idx), crv.zero())
        + (g1 + sum((attr_generators[i] * attrs[i] for i in disclosed_idx), crv.zero()))
        * (-c)
    )

    c_host = sha256(
        cbor.encode(
            [
                Abar.to_sec1_uncompressed(),
                Bbar.to_sec1_uncompressed(),
                D.to_sec1_uncompressed(),
                g1.to_sec1_uncompressed(),
                g1.to_sec1_uncompressed(),
                [gen.to_sec1_uncompressed() for gen in attr_generators],
                len(attr_generators) + 1,
                t1.to_sec1_uncompressed(),
                [crv.scalar_to_big_endian(attrs[i]) for i in sorted(disclosed_idx)],
                sorted(disclosed_idx),
                pk.to_sec1_uncompressed(),
            ]
        )
    )
    cv = int.from_bytes(sha256(n + t2.to_sec1_uncompressed() + c_host), "big") % crv.n
    return cv == c


CRV_BLS = Curve(
    0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB,
    0,
    4,
    0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
    0x396C8C005555E1568C00AAAB0000AAAB,
    48,
    32,
    (
        0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB,
        0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1,
    ),
)
