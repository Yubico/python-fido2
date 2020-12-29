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

from __future__ import absolute_import, unicode_literals

from .cose import CoseKey, ES256
from ._tpm import TpmAttestationFormat, TpmPublicFormat
from .utils import sha256, websafe_decode
from enum import Enum, auto
from cryptography import x509
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives import hashes
import abc
import json


class InvalidAttestation(Exception):
    pass


class InvalidData(InvalidAttestation):
    pass


class InvalidSignature(InvalidAttestation):
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


class AttestationResult(object):
    def __init__(self, attestation_type, trust_path):
        self.attestation_type = attestation_type
        self.trust_path = trust_path

    def verify_trust_path(self, ca=None):
        if not self.trust_path and not ca:
            return
        certs = [
            x509.load_der_x509_certificate(der, default_backend())
            for der in self.trust_path + ([ca] if ca else [])
        ]
        cert = certs.pop(0)
        while certs:
            child = cert
            cert = certs.pop(0)
            pub = cert.public_key()
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


class AttestationType(Enum):
    BASIC = auto()
    SELF = auto()
    ATT_CA = auto()
    ANON_CA = auto()
    NONE = auto


class Attestation(abc.ABC):
    @abc.abstractmethod
    def verify(self, statement, auth_data, client_data_hash):
        pass

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


class FidoU2FAttestation(Attestation):
    FORMAT = "fido-u2f"

    def verify(self, statement, auth_data, client_data_hash):
        cd = auth_data.credential_data
        pk = b"\x04" + cd.public_key[-2] + cd.public_key[-3]
        x5c = statement["x5c"]
        FidoU2FAttestation.verify_signature(
            auth_data.rp_id_hash,
            client_data_hash,
            cd.credential_id,
            pk,
            x5c[0],
            statement["sig"],
        )
        return AttestationResult(AttestationType.BASIC, x5c)

    @staticmethod
    def verify_signature(
        app_param, client_param, key_handle, public_key, cert_bytes, signature
    ):
        m = b"\0" + app_param + client_param + key_handle + public_key
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        try:
            ES256.from_cryptography_key(cert.public_key()).verify(m, signature)
        except _InvalidSignature:
            raise InvalidSignature()


class AndroidSafetynetAttestation(Attestation):
    FORMAT = "android-safetynet"

    def __init__(self, allow_rooted=False):
        self.allow_rooted = allow_rooted

    def verify(self, statement, auth_data, client_data_hash):
        jwt = statement["response"]
        header, payload, sig = (websafe_decode(x) for x in jwt.split(b"."))
        data = json.loads(payload.decode("utf8"))
        if not self.allow_rooted and data["ctsProfileMatch"] is not True:
            raise InvalidData("ctsProfileMatch must be true!")
        expected_nonce = sha256(auth_data + client_data_hash)
        if not bytes_eq(expected_nonce, websafe_decode(data["nonce"])):
            raise InvalidData("Nonce does not match!")

        data = json.loads(header.decode("utf8"))
        x5c = [websafe_decode(x) for x in data["x5c"]]
        cert = x509.load_der_x509_certificate(x5c[0], default_backend())

        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn[0].value != "attest.android.com":
            raise InvalidData("Certificate not issued to attest.android.com!")

        CoseKey.for_name(data["alg"]).from_cryptography_key(cert.public_key()).verify(
            jwt.rsplit(b".", 1)[0], sig
        )
        return AttestationResult(AttestationType.BASIC, x5c)


OID_AAGUID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")


def _validate_cert_common(cert):
    if cert.version != x509.Version.v3:
        raise InvalidData("Attestation certificate must use version 3!")

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            raise InvalidData("Attestation certificate must have CA=false!")
    except x509.ExtensionNotFound:
        raise InvalidData("Attestation certificate must have Basic Constraints!")


def _validate_packed_cert(cert, aaguid):
    # https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements
    _validate_cert_common(cert)

    c = cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    if not c:
        raise InvalidData("Subject must have C set!")
    o = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    if not o:
        raise InvalidData("Subject must have O set!")
    ous = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
    if not ous:
        raise InvalidData('Subject must have OU = "Authenticator Attestation"!')

    ou = ous[0]
    if ou.value != "Authenticator Attestation":
        raise InvalidData('Subject must have OU = "Authenticator Attestation"!')
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn:
        raise InvalidData("Subject must have CN set!")

    try:
        ext = cert.extensions.get_extension_for_oid(OID_AAGUID)
        if ext.critical:
            raise InvalidData("AAGUID extension must not be marked as critical")
        ext_aaguid = ext.value.value[2:]
        if ext_aaguid != aaguid:
            raise InvalidData(
                "AAGUID in Authenticator data does not "
                "match attestation certificate!"
            )
    except x509.ExtensionNotFound:
        pass  # If missing, ignore


class PackedAttestation(Attestation):
    FORMAT = "packed"

    def verify(self, statement, auth_data, client_data_hash):
        if "ecdaaKeyId" in statement:
            raise NotImplementedError("ECDAA not implemented")
        alg = statement["alg"]
        x5c = statement.get("x5c")
        if x5c:
            cert = x509.load_der_x509_certificate(x5c[0], default_backend())
            _validate_packed_cert(cert, auth_data.credential_data.aaguid)

            pub_key = CoseKey.for_alg(alg).from_cryptography_key(cert.public_key())
            att_type = AttestationType.BASIC
        else:
            pub_key = CoseKey.parse(auth_data.credential_data.public_key)
            if pub_key.ALGORITHM != alg:
                raise InvalidData("Wrong algorithm of public key!")
            att_type = AttestationType.SELF
        try:
            pub_key.verify(auth_data + client_data_hash, statement["sig"])
            return AttestationResult(att_type, x5c or [])
        except _InvalidSignature:
            raise InvalidSignature()


OID_AIK_CERTIFICATE = x509.ObjectIdentifier("2.23.133.8.3")


def _validate_tpm_cert(cert):
    # https://www.w3.org/TR/webauthn/#tpm-cert-requirements
    _validate_cert_common(cert)

    s = cert.subject.get_attributes_for_oid(x509.NameOID)
    if s:
        raise InvalidData("Certificate should not have Subject")

    s = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    if not s:
        raise InvalidData("Certificate should have SubjectAlternativeName")
    ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    has_aik = [x == OID_AIK_CERTIFICATE for x in ext.value]
    if True not in has_aik:
        raise InvalidData(
            'Extended key usage MUST contain the "joint-iso-itu-t(2) '
            "internationalorganizations(23) 133 tcg-kp(8) "
            'tcg-kp-AIKCertificate(3)" OID.'
        )


class TpmAttestation(Attestation):
    FORMAT = "tpm"

    def verify(self, statement, auth_data, client_data_hash):
        if "ecdaaKeyId" in statement:
            raise NotImplementedError("ECDAA not implemented")
        alg = statement["alg"]
        x5c = statement["x5c"]
        cert_info = statement["certInfo"]
        cert = x509.load_der_x509_certificate(x5c[0], default_backend())
        _validate_tpm_cert(cert)

        pub_key = CoseKey.for_alg(alg).from_cryptography_key(cert.public_key())

        try:
            pub_area = TpmPublicFormat.parse(statement["pubArea"])
        except Exception as e:
            raise InvalidData("unable to parse pubArea", e)

        # Verify that the public key specified by the parameters and unique
        # fields of pubArea is identical to the credentialPublicKey in the
        # attestedCredentialData in authenticatorData.
        if (
            auth_data.credential_data.public_key.from_cryptography_key(
                pub_area.public_key()
            )
            != auth_data.credential_data.public_key
        ):
            raise InvalidSignature(
                "attestation pubArea does not match attestedCredentialData"
            )

        try:
            # TpmAttestationFormat.parse is reponsible for:
            #   Verify that magic is set to TPM_GENERATED_VALUE.
            #   Verify that type is set to TPM_ST_ATTEST_CERTIFY.
            tpm = TpmAttestationFormat.parse(cert_info)

            # Verify that extraData is set to the hash of attToBeSigned
            # using the hash algorithm employed in "alg".
            att_to_be_signed = auth_data + client_data_hash
            digest = hashes.Hash(pub_key._HASH_ALG, backend=default_backend())
            digest.update(att_to_be_signed)
            data = digest.finalize()

            if tpm.data != data:
                raise InvalidSignature(
                    "attestation does not sign for authData and ClientData"
                )

            # Verify that attested contains a TPMS_CERTIFY_INFO structure as
            # specified in [TPMv2-Part2] section 10.12.3, whose name field
            # contains a valid Name for pubArea, as computed using the
            # algorithm in the nameAlg field of pubArea using the procedure
            # specified in [TPMv2-Part1] section 16.
            # [TPMv2-Part2]:
            # https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
            # [TPMv2-Part1]:
            # https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
            if tpm.attested.name != pub_area.name():
                raise InvalidData(
                    "TPMS_CERTIFY_INFO does not include a valid name for pubArea"
                )

            pub_key.verify(cert_info, statement["sig"])
            return AttestationResult(AttestationType.ATT_CA, x5c)
        except _InvalidSignature:
            raise InvalidSignature("signature of certInfo does not match")


OID_APPLE = x509.ObjectIdentifier("1.2.840.113635.100.8.2")


class AppleAttestation(Attestation):
    FORMAT = "apple"

    def verify(self, statement, auth_data, client_data_hash):
        x5c = statement["x5c"]
        expected_nonce = sha256(auth_data + client_data_hash)
        cert = x509.load_der_x509_certificate(x5c[0], default_backend())
        ext = cert.extensions.get_extension_for_oid(OID_APPLE)
        ext_nonce = ext.value.value[6:]  # Sequence of single element of octet string
        if not bytes_eq(expected_nonce, ext_nonce):
            raise InvalidData("Nonce does not match!")
        return AttestationResult(AttestationType.ANON_CA, x5c)
