# -*- coding: utf-8 -*-

# Copyright (c) 2019 Yubico AB
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

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import cast

from _fido2_native.x509 import Certificate

from ..cose import CoseKey
from ..utils import bytes2int, int2bytes
from .base import (
    Attestation,
    AttestationResult,
    AttestationType,
    InvalidData,
    InvalidSignature,
    _validate_cert_common,
    catch_builtins,
)

TPM_ALG_NULL = 0x0010
OID_AIK_CERTIFICATE = "2.23.133.8.3"


@unique
class TpmRsaScheme(IntEnum):
    RSASSA = 0x0014
    RSAPSS = 0x0016
    OAEP = 0x0017
    RSAES = 0x0015


@unique
class TpmAlgAsym(IntEnum):
    RSA = 0x0001
    ECC = 0x0023


@unique
class TpmAlgHash(IntEnum):
    SHA1 = 0x0004
    SHA256 = 0x000B
    SHA384 = 0x000C
    SHA512 = 0x000D

    def _hashlib_name(self) -> str:
        if self == TpmAlgHash.SHA1:
            return "sha1"
        elif self == TpmAlgHash.SHA256:
            return "sha256"
        elif self == TpmAlgHash.SHA384:
            return "sha384"
        elif self == TpmAlgHash.SHA512:
            return "sha512"

        raise NotImplementedError(f"_hashlib_name is not implemented for {self!r}")


@dataclass
class TpmsCertifyInfo:
    name: bytes
    qualified_name: bytes


TPM_GENERATED_VALUE = b"\xffTCG"
TPM_ST_ATTEST_CERTIFY = b"\x80\x17"


@dataclass
class TpmAttestationFormat:
    """the signature data is defined by [TPMv2-Part2] Section 10.12.8 (TPMS_ATTEST)
    as:
      TPM_GENERATED_VALUE (0xff544347 aka "\xffTCG")
      TPMI_ST_ATTEST - always TPM_ST_ATTEST_CERTIFY (0x8017)
        because signing procedure defines it should call TPM_Certify
        [TPMv2-Part3] Section 18.2
      TPM2B_NAME
        size (uint16)
        name (size long)
      TPM2B_DATA
        size (uint16)
        name (size long)
      TPMS_CLOCK_INFO
        clock (uint64)
        resetCount (uint32)
        restartCount (uint32)
        safe (byte) 1 yes, 0 no
      firmwareVersion uint64
      attested TPMS_CERTIFY_INFO (because TPM_ST_ATTEST_CERTIFY)
        name TPM2B_NAME
        qualified_name TPM2B_NAME
    See:
      https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
      https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
    """

    name: bytes
    data: bytes
    clock_info: tuple[int, int, int, bool]
    firmware_version: int
    attested: TpmsCertifyInfo

    @classmethod
    def parse(cls, data: bytes) -> TpmAttestationFormat:
        offset = 0
        generated_value = data[offset : offset + 4]
        offset += 4

        # Verify that magic is set to TPM_GENERATED_VALUE.
        # see https://w3c.github.io/webauthn/#sctn-tpm-attestation
        #     verification procedure
        if generated_value != TPM_GENERATED_VALUE:
            raise ValueError("generated value field is invalid")

        # Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        # see https://w3c.github.io/webauthn/#sctn-tpm-attestation
        #     verification procedure
        tpmi_st_attest = data[offset : offset + 2]
        offset += 2
        if tpmi_st_attest != TPM_ST_ATTEST_CERTIFY:
            raise ValueError("tpmi_st_attest field is invalid")

        try:
            name_len = struct.unpack_from("!H", data, offset)[0]
            offset += 2
            name = data[offset : offset + name_len]
            offset += name_len

            data_len = struct.unpack_from("!H", data, offset)[0]
            offset += 2
            extra_data = data[offset : offset + data_len]
            offset += data_len

            clock = struct.unpack_from("!Q", data, offset)[0]
            offset += 8
            reset_count = struct.unpack_from("!L", data, offset)[0]
            offset += 4
            restart_count = struct.unpack_from("!L", data, offset)[0]
            offset += 4
            safe_value = struct.unpack_from("B", data, offset)[0]
            offset += 1
            if safe_value not in (0, 1):
                raise ValueError(f"invalid value 0x{safe_value:x} for boolean")
            safe = safe_value == 1

            firmware_version = struct.unpack_from("!Q", data, offset)[0]
            offset += 8

            attested_name_len = struct.unpack_from("!H", data, offset)[0]
            offset += 2
            attested_name = data[offset : offset + attested_name_len]
            offset += attested_name_len

            attested_qn_len = struct.unpack_from("!H", data, offset)[0]
            offset += 2
            attested_qualified_name = data[offset : offset + attested_qn_len]
            offset += attested_qn_len
        except struct.error as e:
            raise ValueError(e)

        return cls(
            name=name,
            data=extra_data,
            clock_info=(clock, reset_count, restart_count, safe),
            firmware_version=firmware_version,
            attested=TpmsCertifyInfo(
                name=attested_name, qualified_name=attested_qualified_name
            ),
        )


@dataclass
class TpmsRsaParms:
    """Parse TPMS_RSA_PARMS struct

    See:
    https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    section 12.2.3.5
    """

    symmetric: int
    scheme: int
    key_bits: int
    exponent: int

    @classmethod
    def parse(
        cls, data: bytes, offset: int, attributes: int
    ) -> tuple[TpmsRsaParms, int]:
        symmetric = struct.unpack_from("!H", data, offset)[0]
        offset += 2

        restricted_decryption = attributes & (
            ATTRIBUTES.RESTRICTED | ATTRIBUTES.DECRYPT
        )
        is_restricted_decryption_key = restricted_decryption == (
            ATTRIBUTES.DECRYPT | ATTRIBUTES.RESTRICTED
        )
        if not is_restricted_decryption_key and symmetric != TPM_ALG_NULL:
            # if the key is not a restricted decryption key, this field
            # shall be set to TPM_ALG_NULL.
            raise ValueError("symmetric is expected to be NULL")
        # Otherwise should be set to a supported symmetric algorithm, keysize and mode
        # TODO(baloo): Should we have non-null value here, do we expect more data?

        scheme = struct.unpack_from("!H", data, offset)[0]
        offset += 2

        restricted_sign = attributes & (ATTRIBUTES.RESTRICTED | ATTRIBUTES.SIGN_ENCRYPT)
        is_unrestricted_signing_key = restricted_sign == ATTRIBUTES.SIGN_ENCRYPT
        if is_unrestricted_signing_key and scheme not in (
            TPM_ALG_NULL,
            TpmRsaScheme.RSASSA,
            TpmRsaScheme.RSAPSS,
        ):
            raise ValueError(
                "key is an unrestricted signing key, scheme is "
                "expected to be TPM_ALG_RSAPSS, TPM_ALG_RSASSA, "
                "or TPM_ALG_NULL"
            )

        is_restricted_signing_key = restricted_sign == (
            ATTRIBUTES.RESTRICTED | ATTRIBUTES.SIGN_ENCRYPT
        )
        if is_restricted_signing_key and scheme not in (
            TpmRsaScheme.RSASSA,
            TpmRsaScheme.RSAPSS,
        ):
            raise ValueError(
                "key is a restricted signing key, scheme is "
                "expected to be TPM_ALG_RSAPSS, or TPM_ALG_RSASSA"
            )

        is_unrestricted_decryption_key = restricted_decryption == ATTRIBUTES.DECRYPT
        if is_unrestricted_decryption_key and scheme not in (
            TpmRsaScheme.OAEP,
            TpmRsaScheme.RSAES,
            TPM_ALG_NULL,
        ):
            raise ValueError(
                "key is an unrestricted decryption key, scheme is "
                "expected to be TPM_ALG_RSAES, TPM_ALG_OAEP, or "
                "TPM_ALG_NULL"
            )

        if is_restricted_decryption_key and scheme not in (TPM_ALG_NULL,):
            raise ValueError(
                "key is an restricted decryption key, scheme is "
                "expected to be TPM_ALG_NULL"
            )

        key_bits = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        exponent = struct.unpack_from("!L", data, offset)[0]
        offset += 4
        if exponent == 0:
            # When  zero,  indicates  that  the  exponent  is  the  default  of 2^16 + 1
            exponent = (2**16) + 1

        return cls(symmetric, scheme, key_bits, exponent), offset


class Tpm2bPublicKeyRsa(bytes):
    @classmethod
    def parse(cls, data: bytes, offset: int) -> tuple[Tpm2bPublicKeyRsa, int]:
        length = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        value = data[offset : offset + length]
        offset += length
        return cls(value), offset


@unique
class TpmEccCurve(IntEnum):
    """TPM_ECC_CURVE
    https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    section 6.4
    """

    NONE = 0x0000
    NIST_P192 = 0x0001
    NIST_P224 = 0x0002
    NIST_P256 = 0x0003
    NIST_P384 = 0x0004
    NIST_P521 = 0x0005
    BN_P256 = 0x0010
    BN_P638 = 0x0011
    SM2_P256 = 0x0020

    def to_cose_curve_id(self) -> int:
        if self == TpmEccCurve.NIST_P256:
            return 1
        elif self == TpmEccCurve.NIST_P384:
            return 2
        elif self == TpmEccCurve.NIST_P521:
            return 3

        raise ValueError("curve is not supported", self)


@unique
class TpmiAlgKdf(IntEnum):
    """TPMI_ALG_KDF
    https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    section 9.28
    """

    NULL = TPM_ALG_NULL
    KDF1_SP800_56A = 0x0020
    KDF2 = 0x0021
    KDF1_SP800_108 = 0x0022


@dataclass
class TpmsEccParms:
    symmetric: int
    scheme: int
    curve_id: TpmEccCurve
    kdf: TpmiAlgKdf

    @classmethod
    def parse(cls, data: bytes, offset: int) -> tuple[TpmsEccParms, int]:
        symmetric = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        scheme = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        if symmetric != TPM_ALG_NULL:
            raise ValueError("symmetric is expected to be NULL")
        if scheme != TPM_ALG_NULL:
            raise ValueError("scheme is expected to be NULL")

        curve_id = TpmEccCurve(struct.unpack_from("!H", data, offset)[0])
        offset += 2
        kdf_scheme = TpmiAlgKdf(struct.unpack_from("!H", data, offset)[0])
        offset += 2

        return cls(symmetric, scheme, curve_id, kdf_scheme), offset


@dataclass
class TpmsEccPoint:
    """TPMS_ECC_POINT
    https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    Section 11.2.5.2
    """

    x: bytes
    y: bytes

    @classmethod
    def parse(cls, data: bytes, offset: int) -> tuple[TpmsEccPoint, int]:
        x_len = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        x = data[offset : offset + x_len]
        offset += x_len

        y_len = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        y = data[offset : offset + y_len]
        offset += y_len

        return cls(x, y), offset


@unique
class ATTRIBUTES(IntEnum):
    """Object attributes
    see section 8.3
      https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    """

    FIXED_TPM = 1 << 1
    ST_CLEAR = 1 << 2
    FIXED_PARENT = 1 << 4
    SENSITIVE_DATA_ORIGIN = 1 << 5
    USER_WITH_AUTH = 1 << 6
    ADMIN_WITH_POLICY = 1 << 7
    NO_DA = 1 << 10
    ENCRYPTED_DUPLICATION = 1 << 11
    RESTRICTED = 1 << 16
    DECRYPT = 1 << 17
    SIGN_ENCRYPT = 1 << 18

    SHALL_BE_ZERO = (
        (1 << 0)  # 0 Reserved
        | (1 << 3)  # 3 Reserved
        | (0x3 << 8)  # 9:8 Reserved
        | (0xF << 12)  # 15:12 Reserved
        | ((0xFFFFFFFF << 19) & (2**32 - 1))  # 31:19 Reserved
    )


_Parameters = TpmsRsaParms | TpmsEccParms
_Unique = Tpm2bPublicKeyRsa | TpmsEccPoint


@dataclass
class TpmPublicFormat:
    """the public area structure is defined by [TPMv2-Part2] Section 12.2.4
    (TPMT_PUBLIC)
    as:
      TPMI_ALG_PUBLIC - type
      TPMI_ALG_HASH - nameAlg
        or + to indicate TPM_ALG_NULL
      TPMA_OBJECT - objectAttributes
      TPM2B_DIGEST - authPolicy
      TPMU_PUBLIC_PARMS - type parameters
      TPMU_PUBLIC_ID - uniq
    See:
      https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    """

    sign_alg: TpmAlgAsym
    name_alg: TpmAlgHash
    attributes: int
    auth_policy: bytes
    parameters: _Parameters
    unique: _Unique
    data: bytes

    @classmethod
    def parse(cls, data: bytes) -> TpmPublicFormat:
        offset = 0
        sign_alg = TpmAlgAsym(struct.unpack_from("!H", data, offset)[0])
        offset += 2
        name_alg = TpmAlgHash(struct.unpack_from("!H", data, offset)[0])
        offset += 2

        attributes = struct.unpack_from("!L", data, offset)[0]
        offset += 4
        if attributes & ATTRIBUTES.SHALL_BE_ZERO != 0:
            raise ValueError(f"attributes is not formated correctly: 0x{attributes:x}")

        auth_policy_len = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        auth_policy = data[offset : offset + auth_policy_len]
        offset += auth_policy_len

        if sign_alg == TpmAlgAsym.RSA:
            parameters: _Parameters
            parameters, offset = TpmsRsaParms.parse(data, offset, attributes)
            unique: _Unique
            unique, offset = Tpm2bPublicKeyRsa.parse(data, offset)
        elif sign_alg == TpmAlgAsym.ECC:
            parameters, offset = TpmsEccParms.parse(data, offset)
            unique, offset = TpmsEccPoint.parse(data, offset)
        else:
            raise NotImplementedError(f"sign alg {sign_alg:x} is not supported")

        if offset != len(data):
            raise ValueError("there should not be any data left in buffer")

        return cls(
            sign_alg, name_alg, attributes, auth_policy, parameters, unique, data
        )

    def public_key_cose(self) -> dict[int, object]:
        """Build a COSE key dict from the TPM public area parameters."""
        if self.sign_alg == TpmAlgAsym.RSA:
            exponent = cast(TpmsRsaParms, self.parameters).exponent
            unique = cast(Tpm2bPublicKeyRsa, self.unique)
            return {
                1: 3,
                -1: bytes(unique),
                -2: int2bytes(exponent),
            }
        elif self.sign_alg == TpmAlgAsym.ECC:
            ecc_unique = cast(TpmsEccPoint, self.unique)
            curve_id = cast(TpmsEccParms, self.parameters).curve_id
            return {
                1: 2,
                -1: curve_id.to_cose_curve_id(),
                -2: ecc_unique.x,
                -3: ecc_unique.y,
            }

        raise NotImplementedError(
            f"public_key_cose not implemented for {self.sign_alg!r}"
        )

    def name(self) -> bytes:
        """
        Computing Entity Names

        see:
          https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
        section 16 Names

        Name ≔ nameAlg || HnameAlg (handle→nvPublicArea)
          where
            nameAlg algorithm used to compute Name
            HnameAlg hash using the nameAlg parameter in the NV Index location
                     associated with handle
            nvPublicArea contents of the TPMS_NV_PUBLIC associated with handle
        """
        output = struct.pack("!H", self.name_alg)
        h = hashlib.new(self.name_alg._hashlib_name())
        h.update(self.data)
        output += h.digest()
        return output


def _validate_tpm_cert(cert):
    # https://www.w3.org/TR/webauthn/#tpm-cert-requirements
    _validate_cert_common(cert)

    if not cert.subject_is_empty():
        raise InvalidData("Certificate should not have Subject")

    if not cert.has_subject_alternative_name():
        raise InvalidData("Certificate should have SubjectAlternativeName")
    if not cert.extended_key_usage_contains(OID_AIK_CERTIFICATE):
        raise InvalidData(
            'Extended key usage MUST contain the "joint-iso-itu-t(2) '
            "internationalorganizations(23) 133 tcg-kp(8) "
            'tcg-kp-AIKCertificate(3)" OID.'
        )


_ALG_HASH_NAME: dict[int, str] = {
    -7: "sha256",  # ES256
    -9: "sha256",  # ESP256
    -35: "sha384",  # ES384
    -36: "sha512",  # ES512
    -37: "sha256",  # PS256
    -47: "sha256",  # ES256K
    -257: "sha256",  # RS256
    -65535: "sha1",  # RS1
}


def _tpm_key_matches(tpm_key: dict[int, object], cred_key: CoseKey) -> bool:
    """Check if TPM pubArea key parameters match the credential public key."""
    kty = tpm_key.get(1)
    if kty == 2:  # EC
        return (
            tpm_key.get(-1) == cred_key.get(-1)
            and bytes2int(tpm_key[-2]) == bytes2int(cred_key[-2])  # type: ignore
            and bytes2int(tpm_key[-3]) == bytes2int(cred_key[-3])  # type: ignore
        )
    elif kty == 3:  # RSA
        return (
            bytes2int(tpm_key[-1]) == bytes2int(cred_key[-1])  # type: ignore  # n
            and bytes2int(tpm_key[-2]) == bytes2int(cred_key[-2])  # type: ignore  # e
        )
    return False


class TpmAttestation(Attestation):
    FORMAT = "tpm"

    @catch_builtins
    def verify(self, statement, auth_data, client_data_hash):
        if "ecdaaKeyId" in statement:
            raise NotImplementedError("ECDAA not implemented")
        alg = statement["alg"]
        x5c = statement["x5c"]
        cert_info = statement["certInfo"]
        cert = Certificate(x5c[0])
        _validate_tpm_cert(cert)

        pub_key = CoseKey.parse(cert.public_key_as_cose(alg))

        try:
            pub_area = TpmPublicFormat.parse(statement["pubArea"])
        except Exception as e:
            raise InvalidData("unable to parse pubArea", e)

        # Verify that the public key specified by the parameters and unique
        # fields of pubArea is identical to the credentialPublicKey in the
        # attestedCredentialData in authenticatorData.
        assert auth_data.credential_data is not None  # noqa: S101
        cred_key = auth_data.credential_data.public_key
        tpm_key = pub_area.public_key_cose()
        if not _tpm_key_matches(tpm_key, cred_key):
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
            hash_name = _ALG_HASH_NAME.get(alg)
            if hash_name is None:
                raise InvalidData(f"Unknown hash for algorithm {alg}")
            data = hashlib.new(hash_name, att_to_be_signed).digest()

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
        except ValueError:
            raise InvalidSignature("signature of certInfo does not match")
