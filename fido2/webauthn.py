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

from . import cbor
from .cose import CoseKey, ES256
from .utils import sha256, ByteBuffer, _CamelCaseDataObject
from enum import Enum, EnumMeta, unique, IntFlag
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence, Tuple, cast
import struct

"""
Data classes based on the W3C WebAuthn specification (https://www.w3.org/TR/webauthn/).

See the specification for a description and details on their usage.
"""

# Binary types


@dataclass(init=False)
class AttestedCredentialData(bytes):
    aaguid: bytes
    credential_id: bytes
    public_key: CoseKey

    def __init__(self, _):
        super().__init__()

        parsed = AttestedCredentialData._parse(self)
        self.aaguid = parsed[0]
        self.credential_id = parsed[1]
        self.public_key = parsed[2]
        if parsed[3]:
            raise ValueError("Wrong length")

    def __str__(self):  # Override default implementation from bytes.
        return repr(self)

    @staticmethod
    def _parse(data: bytes) -> Tuple[bytes, bytes, CoseKey, bytes]:
        """Parse the components of an AttestedCredentialData from a binary
        string, and return them.

        :param data: A binary string containing an attested credential data.
        :return: AAGUID, credential ID, public key, and remaining data.
        """
        reader = ByteBuffer(data)
        aaguid = reader.read(16)
        cred_id = reader.read(reader.unpack(">H"))
        pub_key, rest = cbor.decode_from(reader.read())
        return aaguid, cred_id, CoseKey.parse(pub_key), rest

    @classmethod
    def create(
        cls, aaguid: bytes, credential_id: bytes, public_key: CoseKey
    ) -> "AttestedCredentialData":
        """Create an AttestedCredentialData by providing its components.

        :param aaguid: The AAGUID of the authenticator.
        :param credential_id: The binary ID of the credential.
        :param public_key: A COSE formatted public key.
        :return: The attested credential data.
        """
        return cls(
            aaguid
            + struct.pack(">H", len(credential_id))
            + credential_id
            + cbor.encode(public_key)
        )

    @classmethod
    def unpack_from(cls, data: bytes) -> Tuple["AttestedCredentialData", bytes]:
        """Unpack an AttestedCredentialData from a byte string, returning it and
        any remaining data.

        :param data: A binary string containing an attested credential data.
        :return: The parsed AttestedCredentialData, and any remaining data from
            the input.
        """
        aaguid, cred_id, pub_key, rest = cls._parse(data)
        return cls.create(aaguid, cred_id, pub_key), rest

    @classmethod
    def from_ctap1(
        cls, key_handle: bytes, public_key: bytes
    ) -> "AttestedCredentialData":
        """Create an AttestatedCredentialData from a CTAP1 RegistrationData instance.

        :param key_handle: The CTAP1 credential key_handle.
        :type key_handle: bytes
        :param public_key: The CTAP1 65 byte public key.
        :type public_key: bytes
        :return: The credential data, using an all-zero AAGUID.
        :rtype: AttestedCredentialData
        """
        return cls.create(
            b"\0" * 16, key_handle, ES256.from_ctap1(public_key)  # AAGUID
        )


@dataclass(init=False)
class AuthenticatorData(bytes):
    """Binary encoding of the authenticator data.

    :param _: The binary representation of the authenticator data.
    :ivar rp_id_hash: SHA256 hash of the RP ID.
    :ivar flags: The flags of the authenticator data, see
        AuthenticatorData.FLAG.
    :ivar counter: The signature counter of the authenticator.
    :ivar credential_data: Attested credential data, if available.
    :ivar extensions: Authenticator extensions, if available.
    """

    @unique
    class FLAG(IntFlag):
        """Authenticator data flags

        See https://www.w3.org/TR/webauthn/#sec-authenticator-data for details
        """

        USER_PRESENT = 0x01
        USER_VERIFIED = 0x04
        ATTESTED = 0x40
        EXTENSION_DATA = 0x80

    rp_id_hash: bytes
    flags: AuthenticatorData.FLAG
    counter: int
    credential_data: Optional[AttestedCredentialData]
    extensions: Optional[Mapping]

    def __init__(self, _):
        super().__init__()

        reader = ByteBuffer(self)
        self.rp_id_hash = reader.read(32)
        self.flags = reader.unpack("B")
        self.counter = reader.unpack(">I")
        rest = reader.read()

        if self.flags & AuthenticatorData.FLAG.ATTESTED:
            self.credential_data, rest = AttestedCredentialData.unpack_from(rest)
        else:
            self.credential_data = None

        if self.flags & AuthenticatorData.FLAG.EXTENSION_DATA:
            self.extensions, rest = cbor.decode_from(rest)
        else:
            self.extensions = None

        if rest:
            raise ValueError("Wrong length")

    def __str__(self):  # Override default implementation from bytes.
        return repr(self)

    @classmethod
    def create(
        cls,
        rp_id_hash: bytes,
        flags: AuthenticatorData.FLAG,
        counter: int,
        credential_data: bytes = b"",
        extensions: Optional[Mapping] = None,
    ):
        """Create an AuthenticatorData instance.

        :param rp_id_hash: SHA256 hash of the RP ID.
        :param flags: Flags of the AuthenticatorData.
        :param counter: Signature counter of the authenticator data.
        :param credential_data: Authenticated credential data (only if attested
            credential data flag is set).
        :param extensions: Authenticator extensions (only if ED flag is set).
        :return: The authenticator data.
        """
        return cls(
            rp_id_hash
            + struct.pack(">BI", flags, counter)
            + credential_data
            + (cbor.encode(extensions) if extensions is not None else b"")
        )

    def is_user_present(self) -> bool:
        """Return true if the User Present flag is set.

        :return: True if User Present is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAG.USER_PRESENT)

    def is_user_verified(self) -> bool:
        """Return true if the User Verified flag is set.

        :return: True if User Verified is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAG.USER_VERIFIED)

    def is_attested(self) -> bool:
        """Return true if the Attested credential data flag is set.

        :return: True if Attested credential data is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAG.ATTESTED)

    def has_extension_data(self) -> bool:
        """Return true if the Extenstion data flag is set.

        :return: True if Extenstion data is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAG.EXTENSION_DATA)


@dataclass(init=False)
class AttestationObject(bytes):  # , Mapping[str, Any]):
    """Binary CBOR encoded attestation object.

    :param _: The binary representation of the attestation object.
    :ivar fmt: The type of attestation used.
    :ivar auth_data: The attested authenticator data.
    :ivar att_statement: The attestation statement.
    """

    fmt: str
    auth_data: AuthenticatorData
    att_stmt: Mapping[str, Any]

    def __init__(self, _):
        super().__init__()

        data = cast(Mapping[str, Any], cbor.decode(bytes(self)))
        self.fmt = data["fmt"]
        self.auth_data = AuthenticatorData(data["authData"])
        self.att_stmt = data["attStmt"]

    def __str__(self):  # Override default implementation from bytes.
        return repr(self)

    @classmethod
    def create(
        cls, fmt: str, auth_data: AuthenticatorData, att_stmt: Mapping[str, Any]
    ) -> AttestationObject:
        return cls(
            cbor.encode({"fmt": fmt, "authData": auth_data, "attStmt": att_stmt})
        )

    @classmethod
    def from_ctap1(cls, app_param: bytes, registration) -> AttestationObject:
        """Create an AttestationObject from a CTAP1 RegistrationData instance.

        :param app_param: SHA256 hash of the RP ID used for the CTAP1 request.
        :type app_param: bytes
        :param registration: The CTAP1 registration data.
        :type registration: RegistrationData
        :return: The attestation object, using the "fido-u2f" format.
        :rtype: AttestationObject
        """
        return cls.create(
            "fido-u2f",
            AuthenticatorData.create(
                app_param,
                AuthenticatorData.FLAG.ATTESTED | AuthenticatorData.FLAG.USER_PRESENT,
                0,
                AttestedCredentialData.from_ctap1(
                    registration.key_handle, registration.public_key
                ),
            ),
            {"x5c": [registration.certificate], "sig": registration.signature},
        )


class _StringEnumMeta(EnumMeta):
    def _get_value(cls, value):
        return None

    def __call__(cls, value, *args, **kwargs):
        try:
            return super().__call__(value, *args, **kwargs)
        except ValueError:
            return cls._get_value(value)


class _StringEnum(str, Enum, metaclass=_StringEnumMeta):
    """Enum of strings for WebAuthn types.

    Unrecognized values are treated as missing.
    """


@unique
class AttestationConveyancePreference(_StringEnum):
    NONE = "none"
    INDIRECT = "indirect"
    DIRECT = "direct"
    ENTERPRISE = "enterprise"


@unique
class UserVerificationRequirement(_StringEnum):
    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


@unique
class ResidentKeyRequirement(_StringEnum):
    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


@unique
class AuthenticatorAttachment(_StringEnum):
    PLATFORM = "platform"
    CROSS_PLATFORM = "cross-platform"


@unique
class AuthenticatorTransport(_StringEnum):
    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    INTERNAL = "internal"


@unique
class PublicKeyCredentialType(_StringEnum):
    PUBLIC_KEY = "public-key"


@dataclass(eq=False)
class PublicKeyCredentialRpEntity(_CamelCaseDataObject):
    name: str
    id: Optional[str] = None

    @property
    def id_hash(self) -> Optional[bytes]:
        """Return SHA256 hash of the identifier."""
        return sha256(self.id.encode("utf8")) if self.id else None


@dataclass(eq=False)
class PublicKeyCredentialUserEntity(_CamelCaseDataObject):
    name: str
    id: bytes
    display_name: Optional[str] = None


@dataclass(eq=False)
class PublicKeyCredentialParameters(_CamelCaseDataObject):
    type: PublicKeyCredentialType
    alg: int

    @classmethod
    def _deserialize_list(cls, value):
        if value is None:
            return None
        items = [cls.from_dict(e) for e in value]
        return [e for e in items if e.type is not None]


@dataclass(eq=False)
class PublicKeyCredentialDescriptor(_CamelCaseDataObject):
    type: PublicKeyCredentialType
    id: bytes
    transports: Optional[Sequence[AuthenticatorTransport]] = None

    @classmethod
    def _deserialize_list(cls, value):
        if value is None:
            return None
        items = [cls.from_dict(e) for e in value]
        return [e for e in items if e.type is not None]


@dataclass(eq=False)
class AuthenticatorSelectionCriteria(_CamelCaseDataObject):
    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    resident_key: Optional[ResidentKeyRequirement] = None
    user_verification: Optional[UserVerificationRequirement] = None
    require_resident_key: Optional[bool] = False

    def __post_init__(self):
        super().__post_init__()

        if self.resident_key is None:
            self.resident_key = (
                ResidentKeyRequirement.REQUIRED
                if self.require_resident_key
                else ResidentKeyRequirement.DISCOURAGED
            )
        self.require_resident_key = self.resident_key == ResidentKeyRequirement.REQUIRED


@dataclass(eq=False)
class PublicKeyCredentialCreationOptions(_CamelCaseDataObject):
    rp: PublicKeyCredentialRpEntity
    user: PublicKeyCredentialUserEntity
    challenge: bytes
    pub_key_cred_params: Sequence[PublicKeyCredentialParameters] = field(
        metadata=dict(deserialize=PublicKeyCredentialParameters._deserialize_list),
    )
    timeout: Optional[int] = None
    exclude_credentials: Optional[Sequence[PublicKeyCredentialDescriptor]] = field(
        default=None,
        metadata=dict(deserialize=PublicKeyCredentialDescriptor._deserialize_list),
    )
    authenticator_selection: Optional[AuthenticatorSelectionCriteria] = None
    attestation: Optional[AttestationConveyancePreference] = None
    extensions: Optional[Mapping[str, Any]] = None


@dataclass(eq=False)
class PublicKeyCredentialRequestOptions(_CamelCaseDataObject):
    challenge: bytes
    timeout: Optional[int] = None
    rp_id: Optional[str] = None
    allow_credentials: Optional[Sequence[PublicKeyCredentialDescriptor]] = field(
        default=None,
        metadata={"deserialize": PublicKeyCredentialDescriptor._deserialize_list},
    )
    user_verification: Optional[UserVerificationRequirement] = None
    extensions: Optional[Mapping[str, Any]] = None


@dataclass(eq=False)
class AuthenticatorAttestationResponse(_CamelCaseDataObject):
    client_data: bytes
    attestation_object: AttestationObject
    extension_results: Optional[Mapping[str, Any]] = None


@dataclass(eq=False)
class AuthenticatorAssertionResponse(_CamelCaseDataObject):
    client_data: bytes
    authenticator_data: AuthenticatorData
    signature: bytes
    user_handle: bytes
    credential_id: bytes
    extension_results: Optional[Mapping[str, Any]] = None
