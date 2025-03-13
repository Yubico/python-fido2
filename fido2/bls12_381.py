import math

from cryptography.exceptions import InvalidSignature

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
    s = modpow(n, (primeModulus + 1)//4, primeModulus)
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
        self.generator = PointAffine(gx, gy, self)

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

    def find_bls_generator(self):
        for x in range(0, 100):
            y = self.find_y(x)
            if y is not None:
                g = PointAffine(x, y, self) * self.h
                if g.is_valid_nonzero():
                    return g

    def point_from_cose(self, cose):
        assert cose[1] == 2  # kty: EC2
        assert cose[-1] == -65601  # crv: BLS12-381 (placeholder value)
        assert len(cose[-2]) == self.coord_len
        assert len(cose[-3]) == self.coord_len
        x = int.from_bytes(cose[-2], 'big')
        y = int.from_bytes(cose[-3], 'big')
        return PointAffine(x, y, self).to_projective()

    def point_from_sec1_uncompressed(self, sec1: bytes):
        assert sec1[0] == 0x04
        x = int.from_bytes(sec1[1:(1+self.coord_len)], 'big')
        y = int.from_bytes(sec1[(1+self.coord_len):(1+self.coord_len*2)], 'big')
        return PointAffine(x, y, self).to_projective()


class PointAffine:
    def __init__(self, x, y, crv, is_zero=False):
        self.is_zero = is_zero
        self.x = x
        self.y = y
        self.crv = crv

    def __eq__(self, o):
        assert isinstance(o, PointAffine) or isinstance(o, PointProjective)
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
            l = math.ceil(math.log2(self.crv.p)/8)
            return f"(0x{int.to_bytes(self.x, l, 'big').hex()}, 0x{int.to_bytes(self.y, l, 'big').hex()})"

    def zero(self):
        return PointAffine(0, 0, self.crv, is_zero=True)

    def to_projective(self):
        return PointProjective(self.x, self.y, 1, self.crv)

    def to_sec1_uncompressed(self):
        return bytes([0x04]) + int.to_bytes(self.x, self.crv.coord_len, 'big') + int.to_bytes(self.y, self.crv.coord_len, 'big')

    def is_valid_nonzero(self):
        return not self.is_zero and self.crv.pow(self.y, 2) == (self.crv.pow(self.x, 3) + self.crv.a * self.x + self.crv.b) % self.crv.p

    def __neg__(self):
        return PointAffine(self.x, (-self.y) % self.crv.p, self.crv, is_zero=self.is_zero)

    def __add__(self, q):
        assert isinstance(q, PointAffine)
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
        if self.z == 0 and o.z == 0:
            return True
        elif (self.z == 0) != (o.z == 0):
            return False
        else:
            return (((self.x * o.z) % self.crv.p == (o.x * self.z) % self.crv.p)
                    and ((self.y * o.z) % self.crv.p == (o.y * self.z) % self.crv.p))

    def __repr__(self):
        if self.z == 0:
            return "(ZERO)"
        else:
            l = math.ceil(math.log2(self.crv.p)/8)
            return f"P(0x{int.to_bytes(self.x, l, 'big').hex()}, 0x{int.to_bytes(self.y, l, 'big').hex()}, 0x{int.to_bytes(self.z, l, 'big').hex()})"

    def zero(self):
        return PointProjective(0, 1, 0, self.crv)

    def to_affine(self):
        zinv = modinv(self.z, self.crv.p)
        return PointAffine((self.x * zinv) % self.crv.p, (self.y * zinv) % self.crv.p, self.crv)

    def is_valid_nonzero(self):
        if self.z == 0:
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

        if self.z == 0:
            return q

        elif q.z == 0:
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
                    yr = (2 * p.y) * k * (p.x * zr1 - xr1 * p.z) - 4 * p.z * zr1 * self.crv.pow(p.y, 3)
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
                yr = (pzqz_xpzqmxqzp2 * (q.x*p.y - p.x*q.y) - ypzqmyqzp * k) % self.crv.p
                zr = (pzqz_xpzqmxqzp2 * xpzqmxqzp) % self.crv.p
                return PointProjective(xr, yr, zr, self.crv)

    def __mul__(self, k):
        pPow2 = self
        result = self.zero()

        while k > 0:
            if k % 2 != 0:
                result += pPow2
            pPow2 += pPow2
            k >>= 1

        return result

    def verify_ecsdsa_sha256(self, signature: bytes, message: bytes):
        assert len(signature) == self.crv.scalar_len * 2
        s = int.from_bytes(signature[:self.crv.scalar_len], 'big')
        e = int.from_bytes(signature[self.crv.scalar_len:], 'big')
        rv = self.crv.generator.to_projective() * s + self * e
        rv_bin = rv.to_affine().to_sec1_uncompressed()
        ev_bin = sha256(rv_bin + message)
        ev = int.from_bytes(ev_bin, 'big') % self.crv.n
        if ev == e:
            return
        raise InvalidSignature()


CRV_BLS = Curve(
    0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab,
    0,
    4,
    0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001,
    0x396c8c005555e1568c00aaab0000aaab,
    48,
    32,
    (0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb,
     0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
)
