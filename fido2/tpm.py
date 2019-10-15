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
from binascii import b2a_hex


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
