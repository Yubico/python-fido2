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

from enum import Enum
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from collections import namedtuple
from functools import wraps

import abc


class InvalidAttestation(Exception):
    pass


class InvalidData(InvalidAttestation):
    pass


class InvalidSignature(InvalidAttestation):
    pass


class UntrustedAttestation(InvalidAttestation):
    pass


class UnsupportedType(InvalidAttestation):
    def __init__(self, auth_data, fmt=None):
        super(UnsupportedType, self).__init__(
            'Attestation format "{}" is not supported'.format(fmt)
            if fmt
            else "This attestation format is not supported!"
        )
        self.auth_data = auth_data
        self.fmt = fmt


AttestationResult = namedtuple("AttestationResult", ["attestation_type", "trust_path"])


class AttestationType(Enum):
    BASIC = 1
    SELF = 2
    ATT_CA = 3
    ANON_CA = 4
    NONE = 0


def catch_builtins(f):
    @wraps(f)
    def inner(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (ValueError, KeyError, IndexError) as e:
            raise InvalidData(e)

    return inner


@catch_builtins
def verify_x509_chain(chain):
    certs = [x509.load_der_x509_certificate(der, default_backend()) for der in chain]
    cert = certs.pop(0)
    while certs:
        child = cert
        cert = certs.pop(0)
        pub = cert.public_key()
        try:
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,
                )
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm),
                )
        except _InvalidSignature:
            raise InvalidSignature()


class Attestation(abc.ABC):
    @abc.abstractmethod
    def verify(self, statement, auth_data, client_data_hash):
        """Verifies attestation statement.

        :return: An AttestationResult if successful.
        """

    @staticmethod
    def for_type(fmt):
        for cls in Attestation.__subclasses__():
            if getattr(cls, "FORMAT", None) == fmt:
                return cls

        class TypedUnsupportedAttestation(UnsupportedAttestation):
            def __init__(self):
                super(TypedUnsupportedAttestation, self).__init__(fmt)

        return TypedUnsupportedAttestation


class UnsupportedAttestation(Attestation):
    def __init__(self, fmt=None):
        self.fmt = fmt

    def verify(self, statement, auth_data, client_data_hash):
        raise UnsupportedType(auth_data, self.fmt)


class NoneAttestation(Attestation):
    FORMAT = "none"

    def verify(self, statement, auth_data, client_data_hash):
        if statement != {}:
            raise InvalidData("None Attestation requires empty statement.")
        return AttestationResult(AttestationType.NONE, [])


def _validate_cert_common(cert):
    if cert.version != x509.Version.v3:
        raise InvalidData("Attestation certificate must use version 3!")

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            raise InvalidData("Attestation certificate must have CA=false!")
    except x509.ExtensionNotFound:
        raise InvalidData("Attestation certificate must have Basic Constraints!")
