# Copyright (c) 2018 Yubico AB
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

from __future__ import annotations

from typing import Any, Mapping, Sequence

from _fido2_native.cose import verify as _native_verify


class CoseKey(dict):
    """A COSE formatted public key.

    :param _: The COSE key paramters.
    :cvar ALGORITHM: COSE algorithm identifier.
    """

    ALGORITHM: int = None  # type: ignore

    def verify(self, message: bytes, signature: bytes) -> None:
        """Validates a digital signature over a given message.

        :param message: The message which was signed.
        :param signature: The signature to check.
        """
        _native_verify(self, message, signature)

    @staticmethod
    def for_alg(alg: int) -> type[CoseKey]:
        """Get a subclass of CoseKey corresponding to an algorithm identifier.

        :param alg: The COSE identifier of the algorithm.
        :return: A CoseKey.
        """

        def find_subclass(base_cls: type[CoseKey]) -> type[CoseKey] | None:
            for cls in base_cls.__subclasses__():
                if cls.ALGORITHM == alg:
                    return cls
                subresult = find_subclass(cls)
                if subresult:
                    return subresult
            return None

        return find_subclass(CoseKey) or UnsupportedKey

    @staticmethod
    def for_name(name: str) -> type[CoseKey]:
        """Get a subclass of CoseKey corresponding to an algorithm identifier.

        :param alg: The COSE identifier of the algorithm.
        :return: A CoseKey.
        """

        def find_subclass(base_cls: type[CoseKey]) -> type[CoseKey] | None:
            for cls in base_cls.__subclasses__():
                if cls.__name__ == name:
                    return cls
                subresult = find_subclass(cls)
                if subresult:
                    return subresult
            return None

        return find_subclass(CoseKey) or UnsupportedKey

    @staticmethod
    def parse(cose: Mapping[int, Any]) -> CoseKey:
        """Create a CoseKey from a dict"""
        alg = cose.get(3)
        if not alg:
            raise ValueError("COSE alg identifier must be provided.")
        return CoseKey.for_alg(alg)(cose)

    @staticmethod
    def supported_algorithms() -> Sequence[int]:
        """Get a list of all supported algorithm identifiers"""
        algs: Sequence[type[CoseKey]] = [
            ES256,
            EdDSA,
            ES384,
            ES512,
            PS256,
            RS256,
            ES256K,
        ]
        return [cls.ALGORITHM for cls in algs]


class UnsupportedKey(CoseKey):
    """A COSE key with an unsupported algorithm."""

    def verify(self, message, signature):
        raise NotImplementedError("Signature verification not supported.")


class ES256(CoseKey):
    ALGORITHM = -7

    @classmethod
    def from_ctap1(cls, data):
        """Creates an ES256 key from a CTAP1 formatted public key byte string.

        :param data: A 65 byte SECP256R1 public key.
        :return: A ES256 key.
        """
        return cls({1: 2, 3: cls.ALGORITHM, -1: 1, -2: data[1:33], -3: data[33:65]})


class ESP256(ES256):
    # See: https://www.ietf.org/archive/id/draft-ietf-jose-fully-specified-algorithms-10.html#name-elliptic-curve-digital-sign  # noqa:E501
    ALGORITHM = -9


class ES384(CoseKey):
    ALGORITHM = -35


class ESP384(ES384):
    # See: https://www.ietf.org/archive/id/draft-ietf-jose-fully-specified-algorithms-12.html#name-elliptic-curve-digital-sign  # noqa:E501
    ALGORITHM = -51


class ES512(CoseKey):
    ALGORITHM = -36


class ESP512(ES512):
    # See: https://www.ietf.org/archive/id/draft-ietf-jose-fully-specified-algorithms-12.html#name-elliptic-curve-digital-sign  # noqa:E501
    ALGORITHM = -52


class RS256(CoseKey):
    ALGORITHM = -257


class PS256(CoseKey):
    ALGORITHM = -37


class EdDSA(CoseKey):
    ALGORITHM = -8


class Ed25519(EdDSA):
    # See: https://www.ietf.org/archive/id/draft-ietf-jose-fully-specified-algorithms-12.html#name-edwards-curve-digital-signa  # noqa:E501
    ALGORITHM = -19


class Ed448(CoseKey):
    # See: https://www.ietf.org/archive/id/draft-ietf-jose-fully-specified-algorithms-12.html#name-edwards-curve-digital-signa  # noqa:E501
    ALGORITHM = -53


class RS1(CoseKey):
    ALGORITHM = -65535


class ES256K(CoseKey):
    ALGORITHM = -47
