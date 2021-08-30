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

from . import cbor
from .cose import CoseKey, ES256
from .utils import sha256, ByteBuffer
from enum import Enum, unique, IntFlag
from dataclasses import dataclass, fields, field as _field
from typing import Any, Mapping, Optional, Sequence, Tuple, cast
import re
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
    flags: "AuthenticatorData.FLAG"
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
        flags: "AuthenticatorData.FLAG",
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
    ) -> "AttestationObject":
        return cls(
            cbor.encode({"fmt": fmt, "authData": auth_data, "attStmt": att_stmt})
        )

    @classmethod
    def from_ctap1(cls, app_param: bytes, registration) -> "AttestationObject":
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


class _StringEnum(str, Enum):
    @classmethod
    def _wrap(cls, value):
        if value is None:
            return None
        return cls(value)


@unique
class AttestationConveyancePreference(_StringEnum):
    NONE = "none"
    INDIRECT = "indirect"
    DIRECT = "direct"


@unique
class UserVerificationRequirement(_StringEnum):
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


def _snake2camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def _camel2snake(name: str) -> str:
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def field(*, transform=lambda x: x, **kwargs):
    return _field(metadata={"transform": transform}, **kwargs)


class _DataObject(Mapping[str, Any]):
    """Base class for WebAuthn data types, acting both as dict and providing attribute
    access to values. Subclasses should be annotated with @dataclass(eq=False)
    """

    def __post_init__(self):
        self._keys = []
        for f in fields(self):
            transform = f.metadata.get("transform")
            value = getattr(self, f.name)
            if value:
                if transform:
                    setattr(self, f.name, transform(value))
                self._keys.append(_snake2camel(f.name))

    def __getitem__(self, key):
        try:
            return getattr(self, _camel2snake(key))
        except AttributeError as e:
            raise KeyError(e)

    def __iter__(self):
        return iter(self._keys)

    def __len__(self):
        return len(self._keys)

    @classmethod
    def _wrap(cls, data: Optional[Mapping[str, Any]]):
        if data is None:
            return None
        if isinstance(data, cls):
            return data
        return cls(**{_camel2snake(k): v for k, v in data.items()})  # type: ignore

    @classmethod
    def _wrap_list(cls, datas):
        return [cls._wrap(x) for x in datas] if datas is not None else None


@dataclass(eq=False)
class PublicKeyCredentialRpEntity(_DataObject):
    id: str
    name: str

    @property
    def id_hash(self) -> bytes:
        """Return SHA256 hash of the identifier."""
        return sha256(self.id.encode("utf8"))


@dataclass(eq=False)
class PublicKeyCredentialUserEntity(_DataObject):
    id: bytes
    name: str
    display_name: Optional[str] = None


@dataclass(eq=False)
class PublicKeyCredentialParameters(_DataObject):
    type: PublicKeyCredentialType = field(transform=PublicKeyCredentialType)
    alg: int = field()


@dataclass(eq=False)
class PublicKeyCredentialDescriptor(_DataObject):
    type: PublicKeyCredentialType = field(transform=PublicKeyCredentialType)
    id: bytes = field()
    transports: Optional[Sequence[str]] = None


@dataclass(eq=False)
class AuthenticatorSelectionCriteria(_DataObject):
    authenticator_attachment: Optional[AuthenticatorAttachment] = field(
        transform=AuthenticatorAttachment._wrap, default=None
    )
    require_resident_key: Optional[bool] = None
    user_verification: Optional[UserVerificationRequirement] = field(
        transform=UserVerificationRequirement, default=None
    )


@dataclass(eq=False)
class PublicKeyCredentialCreationOptions(_DataObject):
    rp: PublicKeyCredentialRpEntity = field(transform=PublicKeyCredentialRpEntity._wrap)
    user: PublicKeyCredentialUserEntity = field(
        transform=PublicKeyCredentialUserEntity._wrap
    )
    challenge: bytes = field()
    pub_key_cred_params: Sequence[PublicKeyCredentialParameters] = field(
        transform=PublicKeyCredentialParameters._wrap_list
    )
    timeout: Optional[int] = None
    exclude_credentials: Optional[Sequence[PublicKeyCredentialDescriptor]] = field(
        transform=PublicKeyCredentialDescriptor._wrap_list, default=None
    )
    authenticator_selection: Optional[AuthenticatorSelectionCriteria] = field(
        transform=AuthenticatorSelectionCriteria._wrap, default=None
    )
    attestation: Optional[AttestationConveyancePreference] = field(
        transform=AttestationConveyancePreference._wrap, default=None
    )
    extensions: Optional[Mapping[str, Any]] = None


@dataclass(eq=False)
class PublicKeyCredentialRequestOptions(_DataObject):
    challenge: bytes
    timeout: Optional[int] = None
    rp_id: Optional[str] = None
    allow_credentials: Optional[Sequence[PublicKeyCredentialDescriptor]] = field(
        transform=PublicKeyCredentialDescriptor._wrap_list, default=None
    )
    user_verification: Optional[UserVerificationRequirement] = field(
        transform=UserVerificationRequirement._wrap, default=None
    )
    extensions: Optional[Mapping[str, Any]] = None


@dataclass(eq=False)
class AuthenticatorAttestationResponse(_DataObject):
    client_data: bytes
    attestation_object: AttestationObject = field(transform=AttestationObject)
    extension_results: Optional[Mapping[str, Any]] = None


@dataclass(eq=False)
class AuthenticatorAssertionResponse(_DataObject):
    client_data: bytes
    authenticator_data: AuthenticatorData = field(transform=AuthenticatorData)
    signature: bytes = field()
    user_handle: bytes = field()
    credential_id: bytes = field()
    extension_results: Optional[Mapping[str, Any]] = None
