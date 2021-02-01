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

from .. import cbor
from ..ctap import CtapDevice, CtapError
from ..cose import CoseKey, ES256
from ..hid import CTAPHID, CAPABILITY
from ..utils import ByteBuffer
from ..attestation import FidoU2FAttestation

from enum import IntEnum, IntFlag, unique
from dataclasses import dataclass, field, fields, MISSING
from threading import Event
from typing import Mapping, Dict, Any, List, Optional, Tuple, Type, TypeVar, Callable
import struct


def args(*params) -> Dict[int, Any]:
    """Constructs a dict from a list of arguments for sending a CBOR command.
    None elements will be omitted.

    :param params: Arguments, in order, to add to the command.
    :return: The input parameters as a dict.
    """
    return dict((i, v) for i, v in enumerate(params, 1) if v is not None)


_T = TypeVar("_T", bound="_CborDataObject")


@dataclass(init=False)
class _CborDataObject(Mapping[int, Any]):
    def __init__(self, data: Mapping[int, Any]):
        self._data = dict(data)
        for f in fields(self):
            k = f.metadata.get("cbor_field")
            if k:
                transform = f.metadata["transform"]
                if k in data:
                    v = data[k]
                elif f.default is not MISSING:
                    v = f.default
                elif f.default_factory is not MISSING:  # type: ignore
                    v = f.default_factory()  # type: ignore
                    # see https://github.com/python/mypy/issues/6910
                else:
                    raise TypeError(
                        "Input data missing required field %s: %s" % (k, f.name)
                    )
                setattr(self, f.name, transform(v))

    @classmethod
    def parse(cls: Type[_T], binary: bytes) -> _T:
        decoded = cbor.decode(binary)
        if isinstance(decoded, Mapping):
            return cls(decoded)  # type: ignore
        raise TypeError("Decoded value of incorrect type!")

    @classmethod
    def create(cls: Type[_T], **kwargs) -> _T:
        data = {}
        fs = {f.name: f.metadata for f in fields(cls)}
        for name, v in kwargs.items():
            k = fs[name]["cbor_field"]
            data[k] = v
        return cls(data)

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)


def cbor_field(key: int, *, transform=lambda x: x, **kwargs):
    return field(
        init=False, metadata={"cbor_field": key, "transform": transform}, **kwargs
    )


@dataclass(init=False)
class Info(_CborDataObject):
    """Binary CBOR encoded response data returned by the CTAP2 GET_INFO command.

    :param _: The binary content of the Info data.
    :ivar versions: The versions supported by the authenticator.
    :ivar extensions: The extensions supported by the authenticator.
    :ivar aaguid: The AAGUID of the authenticator.
    :ivar options: The options supported by the authenticator.
    :ivar max_msg_size: The max message size supported by the authenticator.
    :ivar pin_uv_protocols: The PIN/UV protocol versions supported by the authenticator.
    :ivar max_creds_in_list: Max number of credentials supported in list at a time.
    :ivar max_cred_id_length: Max length of Credential ID supported.
    :ivar transports: List of supported transports.
    :ivar algorithms: List of supported algorithms for credential creation.
    :ivar data: The Info members, in the form of a dict.
    """

    versions: List[str] = cbor_field(0x01)
    extensions: List[str] = cbor_field(0x02, default_factory=list)
    aaguid: bytes = cbor_field(0x03)
    options: Dict[str, bool] = cbor_field(0x04, default_factory=dict)
    max_msg_size: int = cbor_field(0x05, default=1024)
    pin_uv_protocols: List[int] = cbor_field(0x06, default_factory=list)
    max_creds_in_list: Optional[int] = cbor_field(0x07, default=None)
    max_cred_id_length: Optional[int] = cbor_field(0x08, default=None)
    transports: List[str] = cbor_field(0x09, default_factory=list)
    algorithms: Optional[List[int]] = cbor_field(0x0A, default=None)
    max_large_blob: Optional[int] = cbor_field(0x0B, default=None)
    force_pin_change: bool = cbor_field(0x0C, default=False)
    min_pin_length: int = cbor_field(0x0D, default=4)
    firmware_version: Optional[int] = cbor_field(0x0E, default=None)
    max_cred_blob_length: Optional[int] = cbor_field(0x0F, default=None)
    max_rpids_for_min_pin: int = cbor_field(0x10, default=0)
    preferred_platform_uv_attempts: int = cbor_field(0x11, default=None)
    uv_modality: Optional[int] = cbor_field(0x12, default=None)
    certifications: Optional[Dict] = cbor_field(0x13, default=None)
    remaining_disc_creds: Optional[int] = cbor_field(0x14, default=None)


@dataclass(init=False)
class AttestedCredentialData(bytes):
    aaguid: bytes
    credential_id: bytes
    public_key: CoseKey

    def __init__(self, _):
        super(AttestedCredentialData, self).__init__()

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
        parts = cls._parse(data)
        return cls.create(*parts[:-1]), parts[-1]

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
        AuthenticatorData.FLAGS.
    :ivar counter: The signature counter of the authenticator.
    :ivar credential_data: Attested credential data, if available.
    :ivar extensions: Authenticator extensions, if available.
    """

    @unique
    class FLAGS(IntFlag):
        """Authenticator data flags

        See https://www.w3.org/TR/webauthn/#sec-authenticator-data for details
        """

        USER_PRESENT = 0x01
        USER_VERIFIED = 0x04
        ATTESTED = 0x40
        EXTENSION_DATA = 0x80

    rp_id_hash: bytes
    flags: "AuthenticatorData.FLAGS"
    counter: int
    credential_data: Optional[AttestedCredentialData]
    extensions: Optional[Mapping]

    def __init__(self, _):
        super(AuthenticatorData, self).__init__()

        reader = ByteBuffer(self)
        self.rp_id_hash = reader.read(32)
        self.flags = reader.unpack("B")
        self.counter = reader.unpack(">I")
        rest = reader.read()

        if self.flags & AuthenticatorData.FLAGS.ATTESTED:
            self.credential_data, rest = AttestedCredentialData.unpack_from(rest)
        else:
            self.credential_data = None

        if self.flags & AuthenticatorData.FLAGS.EXTENSION_DATA:
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
        flags: "AuthenticatorData.FLAGS",
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
        return bool(self.flags & AuthenticatorData.FLAGS.USER_PRESENT)

    def is_user_verified(self) -> bool:
        """Return true if the User Verified flag is set.

        :return: True if User Verified is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAGS.USER_VERIFIED)

    def is_attested(self) -> bool:
        """Return true if the Attested credential data flag is set.

        :return: True if Attested credential data is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAGS.ATTESTED)

    def has_extension_data(self) -> bool:
        """Return true if the Extenstion data flag is set.

        :return: True if Extenstion data is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAGS.EXTENSION_DATA)


@dataclass(init=False)
class AttestationObject(_CborDataObject):
    """Binary CBOR encoded attestation object.

    :param _: The binary representation of the attestation object.
    :type _: bytes
    :ivar fmt: The type of attestation used.
    :type fmt: str
    :ivar auth_data: The attested authenticator data.
    :type auth_data: AuthenticatorData
    :ivar att_statement: The attestation statement.
    :type att_statement: Dict[str, Any]
    """

    fmt: str = cbor_field(0x01)
    auth_data: AuthenticatorData = cbor_field(0x02, transform=AuthenticatorData)
    att_statement: Dict[str, Any] = cbor_field(0x03)
    ep_att: Optional[bool] = cbor_field(0x04, default=None)
    large_blob_key: Optional[bytes] = cbor_field(0x05, default=None)

    def get_webauthn(self) -> Dict[str, Any]:
        """Get data formatted as a WebAuthn Attestation Object"""
        return {
            "fmt": self.fmt,
            "attStmt": self.att_statement,
            "authData": self.auth_data,
        }

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
            fmt=FidoU2FAttestation.FORMAT,
            auth_data=AuthenticatorData.create(
                app_param,
                AuthenticatorData.FLAGS.ATTESTED | AuthenticatorData.FLAGS.USER_PRESENT,
                0,
                AttestedCredentialData.from_ctap1(
                    registration.key_handle, registration.public_key
                ),
            ),
            att_statement={
                "x5c": [registration.certificate],
                "sig": registration.signature,
            },
        )


@dataclass(init=False)
class AssertionResponse(_CborDataObject):
    """Binary CBOR encoded assertion response.

    :param _: The binary representation of the assertion response.
    :ivar credential: The credential used for the assertion.
    :ivar auth_data: The authenticator data part of the response.
    :ivar signature: The digital signature of the assertion.
    :ivar user: The user data of the credential.
    :ivar number_of_credentials: The total number of responses available
        (only set for the first response, if > 1).
    """

    credential: Dict[str, Any] = cbor_field(0x01)
    auth_data: AuthenticatorData = cbor_field(0x02, transform=AuthenticatorData)
    signature: bytes = cbor_field(0x03)
    user: Optional[Dict[str, Any]] = cbor_field(0x04, default=None)
    number_of_credentials: Optional[int] = cbor_field(0x05, default=None)
    user_selected: Optional[bool] = cbor_field(0x06, default=None)
    large_blob_key: Optional[bytes] = cbor_field(0x07, default=None)

    def verify(self, client_param: bytes, public_key: CoseKey):
        """Verify the digital signature of the response with regard to the
        client_param, using the given public key.

        :param client_param: SHA256 hash of the ClientData used for the request.
        :param public_key: The public key of the credential, to verify.
        """
        public_key.verify(self.auth_data + client_param, self.signature)

    @classmethod
    def from_ctap1(
        cls, app_param: bytes, credential: Dict[str, Any], authentication
    ) -> "AssertionResponse":
        """Create an AssertionResponse from a CTAP1 SignatureData instance.

        :param app_param: SHA256 hash of the RP ID used for the CTAP1 request.
        :param credential: Credential used for the CTAP1 request (from the
            allowList).
        :param authentication: The CTAP1 signature data.
        :return: The assertion response.
        """
        return cls.create(
            credential=credential,
            auth_data=AuthenticatorData.create(
                app_param, authentication.user_presence & 0x01, authentication.counter
            ),
            signature=authentication.signature,
        )


class Ctap2:
    """Implementation of the CTAP2 specification.

    :param device: A CtapHidDevice handle supporting CTAP2.
    :param strict_cbor: Validate that CBOR returned from the Authenticator is
        canonical, defaults to True.
    """

    @unique
    class CMD(IntEnum):
        MAKE_CREDENTIAL = 0x01
        GET_ASSERTION = 0x02
        GET_INFO = 0x04
        CLIENT_PIN = 0x06
        RESET = 0x07
        GET_NEXT_ASSERTION = 0x08
        BIO_ENROLLMENT = 0x09
        CREDENTIAL_MGMT = 0x0A
        SELECTION = 0x0B
        LARGE_BLOBS = 0x0C
        CONFIG = 0x0D

        BIO_ENROLLMENT_PRE = 0x40
        CREDENTIAL_MGMT_PRE = 0x41

    def __init__(self, device: CtapDevice, strict_cbor: bool = True):
        if not device.capabilities & CAPABILITY.CBOR:
            raise ValueError("Device does not support CTAP2.")
        self.device = device
        self._strict_cbor = strict_cbor
        self._info = self.get_info()

    @property
    def info(self) -> Info:
        """Get a cached Info object which can be used to determine capabilities.

        :rtype: Info
        :return: The response of calling GetAuthenticatorInfo.
        """
        return self._info

    def send_cbor(
        self,
        cmd: int,
        data: Optional[Mapping[int, Any]] = None,
        event: Optional[Event] = None,
        on_keepalive: Optional[Callable[[int], None]] = None,
    ) -> Mapping[int, Any]:
        """Sends a CBOR message to the device, and waits for a response.

        :param cmd: The command byte of the request.
        :param data: The payload to send (to be CBOR encoded).
        :param event: Optional threading.Event used to cancel the request.
        :param parse: Function used to parse the binary response data, defaults
            to parsing the CBOR.
        :param on_keepalive: Optional function called when keep-alive is sent by
            the authenticator.
        :return: The result of calling the parse function on the response data
            (defaults to the CBOR decoded value).
        """
        request = struct.pack(">B", cmd)
        if data is not None:
            request += cbor.encode(data)
        response = self.device.call(CTAPHID.CBOR, request, event, on_keepalive)
        status = response[0]
        if status != 0x00:
            raise CtapError(status)
        enc = response[1:]
        if not enc:
            return {}
        decoded = cbor.decode(enc)
        if self._strict_cbor:
            expected = cbor.encode(decoded)
            if expected != enc:
                enc_h = enc.hex()
                exp_h = expected.hex()
                raise ValueError(
                    "Non-canonical CBOR from Authenticator.\n"
                    "Got: {}\n".format(enc_h) + "Expected: {}".format(exp_h)
                )
        if isinstance(decoded, Mapping):
            return decoded
        raise TypeError("Decoded value of wrong type")

    def get_info(self) -> Info:
        """CTAP2 getInfo command.

        :return: Information about the authenticator.
        """
        return Info(self.send_cbor(Ctap2.CMD.GET_INFO))

    def client_pin(
        self,
        pin_uv_protocol: int,
        sub_cmd: int,
        key_agreement: Optional[Mapping[int, Any]] = None,
        pin_uv_param: Optional[bytes] = None,
        new_pin_enc: Optional[bytes] = None,
        pin_hash_enc: Optional[bytes] = None,
        permissions: Optional[int] = None,
        permissions_rpid: Optional[str] = None,
    ):
        """CTAP2 clientPin command, used for various PIN operations.

        This method is not intended to be called directly. It is intended to be used by
        an instance of the PinProtocolV1 class.

        :param pin_uv_protocol: The PIN/UV protocol version to use.
        :param sub_cmd: A clientPin sub command.
        :param key_agreement: The keyAgreement parameter.
        :param pin_uv_param: The pinAuth parameter.
        :param new_pin_enc: The newPinEnc parameter.
        :param pin_hash_enc: The pinHashEnc parameter.
        :param permissions: The permissions parameter.
        :param permissions_rpid: The permissions RPID parameter.
        :return: The response of the command, decoded.
        """
        return self.send_cbor(
            Ctap2.CMD.CLIENT_PIN,
            args(
                pin_uv_protocol,
                sub_cmd,
                key_agreement,
                pin_uv_param,
                new_pin_enc,
                pin_hash_enc,
                None,
                None,
                permissions,
                permissions_rpid,
            ),
        )

    def reset(
        self,
        event: Optional[Event] = None,
        on_keepalive: Optional[Callable[[int], None]] = None,
    ):
        """CTAP2 reset command, erases all credentials and PIN.

        :param event: Optional threading.Event object used to cancel the request.
        :param on_keepalive: Optional callback function to handle keep-alive
            messages from the authenticator.
        """
        self.send_cbor(Ctap2.CMD.RESET, event=event, on_keepalive=on_keepalive)

    def make_credential(
        self,
        client_data_hash: bytes,
        rp: Mapping[str, Any],
        user: Mapping[str, Any],
        key_params: List[Mapping[str, Any]],
        exclude_list: Optional[List[Mapping[str, Any]]] = None,
        extensions: Optional[Mapping[str, Any]] = None,
        options: Optional[Mapping[str, Any]] = None,
        pin_uv_param: Optional[bytes] = None,
        pin_uv_protocol: Optional[int] = None,
        event: Optional[Event] = None,
        on_keepalive: Optional[Callable[[int], None]] = None,
    ) -> AttestationObject:
        """CTAP2 makeCredential operation.

        :param client_data_hash: SHA256 hash of the ClientData.
        :param rp: PublicKeyCredentialRpEntity parameters.
        :param user: PublicKeyCredentialUserEntity parameters.
        :param key_params: List of acceptable credential types.
        :param exclude_list: Optional list of PublicKeyCredentialDescriptors.
        :param extensions: Optional dict of extensions.
        :param options: Optional dict of options.
        :param pin_uv_param: Optional PIN/UV auth parameter.
        :param pin_uv_protocol: The version of PIN/UV protocol used, if any.
        :param event: Optional threading.Event used to cancel the request.
        :param on_keepalive: Optional callback function to handle keep-alive
            messages from the authenticator.
        :return: The new credential.
        """
        return AttestationObject(
            self.send_cbor(
                Ctap2.CMD.MAKE_CREDENTIAL,
                args(
                    client_data_hash,
                    rp,
                    user,
                    key_params,
                    exclude_list,
                    extensions,
                    options,
                    pin_uv_param,
                    pin_uv_protocol,
                ),
                event,
                on_keepalive,
            )
        )

    def get_assertion(
        self,
        rp_id: str,
        client_data_hash: bytes,
        allow_list: Optional[List[Mapping[str, Any]]] = None,
        extensions: Optional[Mapping[str, Any]] = None,
        options: Optional[Mapping[str, Any]] = None,
        pin_uv_param: Optional[bytes] = None,
        pin_uv_protocol: Optional[int] = None,
        event: Optional[Event] = None,
        on_keepalive: Optional[Callable[[int], None]] = None,
    ) -> AssertionResponse:
        """CTAP2 getAssertion command.

        :param rp_id: The RP ID of the credential.
        :param client_data_hash: SHA256 hash of the ClientData used.
        :param allow_list: Optional list of PublicKeyCredentialDescriptors.
        :param extensions: Optional dict of extensions.
        :param options: Optional dict of options.
        :param pin_uv_param: Optional PIN/UV auth parameter.
        :param pin_uv_protocol: The version of PIN/UV protocol used, if any.
        :param event: Optional threading.Event used to cancel the request.
        :param on_keepalive: Optional callback function to handle keep-alive messages
            from the authenticator.
        :return: The new assertion.
        """
        return AssertionResponse(
            self.send_cbor(
                Ctap2.CMD.GET_ASSERTION,
                args(
                    rp_id,
                    client_data_hash,
                    allow_list,
                    extensions,
                    options,
                    pin_uv_param,
                    pin_uv_protocol,
                ),
                event,
                on_keepalive,
            )
        )

    def get_next_assertion(self) -> AssertionResponse:
        """CTAP2 getNextAssertion command.

        :return: The next available assertion response.
        """
        return AssertionResponse(self.send_cbor(Ctap2.CMD.GET_NEXT_ASSERTION))

    def get_assertions(self, *args, **kwargs) -> List[AssertionResponse]:
        """Convenience method to get list of assertions.

        See get_assertion and get_next_assertion for details.
        """
        first = self.get_assertion(*args, **kwargs)
        rest = [
            self.get_next_assertion()
            for _ in range(1, first.number_of_credentials or 1)
        ]
        return [first] + rest

    def credential_mgmt(
        self,
        sub_cmd: int,
        sub_cmd_params: Optional[Mapping[int, Any]] = None,
        pin_uv_protocol: Optional[int] = None,
        pin_uv_param: Optional[bytes] = None,
    ):
        """CTAP2 credentialManagement command, used to manage resident
        credentials.

        NOTE: This implements the current draft version of the CTAP2 specification and
        should be considered highly experimental.

        This method is not intended to be called directly. It is intended to be used by
        an instance of the CredentialManagement class.

        :param sub_cmd: A CredentialManagement sub command.
        :param sub_cmd_params: Sub command specific parameters.
        :param pin_uv_protocol: PIN/UV auth protocol version used.
        :param pin_uv_param: PIN/UV Auth parameter.
        """
        if "credMgmt" in self.info.options:
            cmd = Ctap2.CMD.CREDENTIAL_MGMT
        elif "credentialMgmtPreview" in self.info.options:
            cmd = Ctap2.CMD.CREDENTIAL_MGMT_PRE
        else:
            raise ValueError(
                "Credential Management not supported by this Authenticator"
            )
        return self.send_cbor(
            cmd, args(sub_cmd, sub_cmd_params, pin_uv_protocol, pin_uv_param)
        )

    def bio_enrollment(
        self,
        modality: Optional[int] = None,
        sub_cmd: Optional[int] = None,
        sub_cmd_params: Optional[Mapping[int, Any]] = None,
        pin_uv_protocol: Optional[int] = None,
        pin_uv_param: Optional[bytes] = None,
        get_modality: Optional[bool] = None,
        event: Optional[Event] = None,
        on_keepalive: Optional[Callable[[int], None]] = None,
    ):
        """CTAP2 bio enrollment command. Used to provision/enumerate/delete bio
        enrollments in the authenticator.

        NOTE: This implements the current draft version of the CTAP2 specification and
        should be considered highly experimental.

        This method is not intended to be called directly. It is intended to be used by
        an instance of the BioEnrollment class.

        :param modality: The user verification modality being used.
        :param sub_cmd: A BioEnrollment sub command.
        :param sub_cmd_params: Sub command specific parameters.
        :param pin_uv_protocol: PIN/UV protocol version used.
        :param pin_uv_param: PIN/UV auth param.
        :param get_modality: Get the user verification type modality.
        """
        if "bioEnroll" in self.info.options:
            cmd = Ctap2.CMD.BIO_ENROLLMENT
        elif "userVerificationMgmtPreview" in self.info.options:
            cmd = Ctap2.CMD.BIO_ENROLLMENT_PRE
        else:
            raise ValueError("Authenticator does not support Bio Enroll")
        return self.send_cbor(
            cmd,
            args(
                modality,
                sub_cmd,
                sub_cmd_params,
                pin_uv_protocol,
                pin_uv_param,
                get_modality,
            ),
            event=event,
            on_keepalive=on_keepalive,
        )

    def selection(
        self,
        event: Optional[Event] = None,
        on_keepalive: Optional[Callable[[int], None]] = None,
    ):
        """CTAP2 authenticator selection command.

        This command allows the platform to let a user select a certain authenticator
        by asking for user presence.

        :param event: Optional threading.Event used to cancel the request.
        :param on_keepalive: Optional callback function to handle keep-alive messages
            from the authenticator.
        """
        self.send_cbor(Ctap2.CMD.SELECTION, event=event, on_keepalive=on_keepalive)

    def large_blobs(
        self,
        offset: int,
        get: Optional[int] = None,
        set: Optional[bytes] = None,
        length: Optional[int] = None,
        pin_uv_param: Optional[bytes] = None,
        pin_uv_protocol: Optional[int] = None,
    ):
        """CTAP2 authenticator large blobs command.

        This command is used to read and write the large blob array.

        This method is not intended to be called directly. It is intended to be used by
        an instance of the LargeBlobs class.

        :param offset: The offset of where to start reading/writing data.
        :param get: Optional (max) length of data to read.
        :param set: Optional data to write.
        :param length: Length of the payload in set.
        :param pin_uv_protocol: PIN/UV protocol version used.
        :param pin_uv_param: PIN/UV auth param.
        """
        return self.send_cbor(
            Ctap2.CMD.LARGE_BLOBS,
            args(get, set, offset, length, pin_uv_param, pin_uv_protocol),
        )

    def config(
        self,
        sub_cmd: int,
        sub_cmd_params: Optional[Mapping[int, Any]] = None,
        pin_uv_protocol: Optional[int] = None,
        pin_uv_param: Optional[bytes] = None,
    ):
        """CTAP2 authenticator config command.

        This command is used to configure various authenticator features through the
        use of its subcommands.

        This method is not intended to be called directly. It is intended to be used by
        an instance of the Config class.

        :param sub_cmd: A Config sub command.
        :param sub_cmd_params: Sub command specific parameters.
        :param pin_uv_protocol: PIN/UV auth protocol version used.
        :param pin_uv_param: PIN/UV Auth parameter.
        """
        return self.send_cbor(
            Ctap2.CMD.CONFIG,
            args(sub_cmd, sub_cmd_params, pin_uv_protocol, pin_uv_param),
        )
