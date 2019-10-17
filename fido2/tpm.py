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

import struct
from io import BytesIO

from enum import IntEnum
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from .utils import bytes2int


TPM_ALG_NULL = 0x0010


class TpmAlgAsym(IntEnum):
    RSA = 0x0001
    ECC = 0x0023


class TpmAlgHash(IntEnum):
    SHA1 = 0x0004
    SHA256 = 0x000B
    SHA384 = 0x000C
    SHA512 = 0x000D


class TpmAttestationFormat(object):
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

    TPM_GENERATED_VALUE = b"\xffTCG"
    TPM_ST_ATTEST_CERTIFY = b"\x80\x17"

    @classmethod
    def parse(cls, data):
        reader = BytesIO(data)
        generated_value = reader.read(4)

        if generated_value != cls.TPM_GENERATED_VALUE:
            raise ValueError("generated value field is invalid")

        tpmi_st_attest = reader.read(2)
        if tpmi_st_attest != cls.TPM_ST_ATTEST_CERTIFY:
            raise ValueError("tpmi_st_attest field is invalid")

        try:
            name_len = struct.unpack("!H", reader.read(2))[0]
            name = reader.read(name_len)
            if name_len != len(name):
                raise ValueError("name is too short")

            data_len = struct.unpack("!H", reader.read(2))[0]
            data = reader.read(data_len)
            if data_len != len(data):
                raise ValueError("data is too short")

            clock = struct.unpack("!Q", reader.read(8))[0]
            reset_count = struct.unpack("!L", reader.read(4))[0]
            restart_count = struct.unpack("!L", reader.read(4))[0]
            safe_value = reader.read(1)
            if safe_value not in (b"\x00", b"\x01"):
                raise ValueError(
                    "invalid value 0x{} for boolean".format(
                        b2a_hex(safe_value).decode("ascii")
                    )
                )
            safe = safe_value == b"\x01"

            firmware_version = struct.unpack("!Q", reader.read(8))[0]

            attested_name_len = struct.unpack("!H", reader.read(2))[0]
            attested_name = reader.read(attested_name_len)
            if attested_name_len != len(attested_name):
                raise ValueError("attested_name is too short")

            attested_qualified_name_len = struct.unpack("!H", reader.read(2))[0]
            attested_qualified_name = reader.read(attested_qualified_name_len)
            if attested_qualified_name_len != len(attested_qualified_name):
                raise ValueError("attested_qualified_name is too short")
        except struct.error as e:
            raise ValueError(e)

        return cls(
            name=name,
            data=data,
            clock_info=(clock, reset_count, restart_count, safe),
            firmware_version=firmware_version,
            attested=(attested_name, attested_qualified_name),
        )

    def __init__(self, name, data, clock_info, firmware_version, attested):
        self.name = name
        self.data = data
        self.clock_info = clock_info
        self.firmware_version = firmware_version
        self.attested = attested

    def __repr__(self):
        return (
            "<TpmAttestationFormat"
            " data={self.data}"
            " name={self.name}"
            " clock_info={self.clock_info}"
            " firmware_version=0x{self.firmware_version:x}"
            " attested={self.attested}"
            ">".format(self=self)
        )


class TpmsRsaParms(object):
    @classmethod
    def parse(cls, reader):
        symmetric = struct.unpack("!H", reader.read(2))[0]
        scheme = struct.unpack("!H", reader.read(2))[0]
        # TODO(baloo): move those assert to an actual check, this is disabled
        #              in production
        assert symmetric == TPM_ALG_NULL
        assert scheme == TPM_ALG_NULL
        key_bits = struct.unpack("!H", reader.read(2))[0]
        exponent = reader.read(4)
        exponent = struct.unpack("!L", exponent)[0]
        if exponent == 0:
            # When  zero,  indicates  that  the  exponent  is  the  default  of 2^16 + 1
            exponent = (2 ** 16) + 1

        return cls(symmetric, scheme, key_bits, exponent)

    def __init__(self, symmetric, scheme, key_bits, exponent):
        self.symmetric = symmetric
        self.scheme = scheme
        self.key_bits = key_bits
        self.exponent = exponent

    def __repr__(self):
        return (
            "<TpmsRsaParms"
            " symmetric=0x{self.symmetric:x}"
            " scheme=0x{self.scheme:x}"
            " key_bits={self.key_bits}"
            " exponent={self.exponent}"
            ">".format(self=self)
        )


class Tpm2bPublicKeyRsa(bytes):
    @classmethod
    def parse(cls, reader):
        size = struct.unpack("!H", reader.read(2))[0]
        buffer = reader.read(size)
        if len(buffer) != size:
            raise ValueError("buffer has not expected length")

        return cls(buffer)


class TpmPublicFormat(object):
    """the public area structure is defined by [TPMv2-Part2] Section 12.2.4 (TPMT_PUBLIC)
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
            | ((0xFFFFFFFF << 19) & (2 ** 32 - 1))  # 31:19 Reserved
        )

    @classmethod
    def parse(cls, data):
        reader = BytesIO(data)
        sign_alg = struct.unpack("!H", reader.read(2))[0]
        sign_alg = TpmAlgAsym(sign_alg)
        hash_alg = struct.unpack("!H", reader.read(2))[0]
        hash_alg = TpmAlgHash(hash_alg)

        attributes = struct.unpack("!L", reader.read(4))[0]
        if attributes & TpmPublicFormat.ATTRIBUTES.SHALL_BE_ZERO != 0:
            raise ValueError(
                "attributes is not formated correctly: " "0x{:x}".format(attributes)
            )

        auth_policy_len = struct.unpack("!H", reader.read(2))[0]
        auth_policy = reader.read(auth_policy_len)
        if auth_policy_len != len(auth_policy):
            raise ValueError("auth policy is too short")

        if sign_alg == TpmAlgAsym.RSA:
            parameters = TpmsRsaParms.parse(reader)
            unique = Tpm2bPublicKeyRsa.parse(reader)
        # TODO(baloo): implement ECC
        # elif sign_alg == TpmAlgAsym.ECC:
        #     parameters = TpmsEccParms.parse(reader)
        #     unique = TpmsEccPoint.parse(reader)
        else:
            raise NotImplementedError(
                "sign alg {:x} is not " "supported".format(sign_alg)
            )

        rest = reader.read(1)
        if len(rest) != 0:
            raise ValueError("there should not be any data left in buffer")

        return cls(sign_alg, hash_alg, attributes, auth_policy, parameters, unique)

    def __init__(self, sign_alg, hash_alg, attributes, auth_policy, parameters, unique):
        self.sign_alg = sign_alg
        self.hash_alg = hash_alg
        self.attributes = attributes
        self.auth_policy = auth_policy
        self.parameters = parameters
        self.unique = unique

    def __repr__(self):
        return (
            "<TpmPublicFormat"
            " sign_alg=0x{self.sign_alg:x}"
            " hash_alg=0x{self.hash_alg:x}"
            " attributes=0x{self.attributes:x}({self.attributes!r})"
            " auth_policy={self.auth_policy}"
            " parameters={self.parameters}"
            " unique={self.unique}"
            ">".format(self=self)
        )

    def public_key(self):
        if self.sign_alg == TpmAlgAsym.RSA:
            exponent = self.parameters.exponent
            modulus = bytes2int(self.unique)
            return rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())

        raise NotImplementedError(
            "public_key not implemented for {0!r}".format(self.sign_alg)
        )
