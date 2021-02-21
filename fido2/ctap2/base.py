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

from .. import cbor
from ..ctap import CtapError
from ..cose import CoseKey, ES256
from ..hid import CTAPHID, CAPABILITY
from ..utils import ByteBuffer
from ..attestation import FidoU2FAttestation

from binascii import b2a_hex
from enum import IntEnum, unique
import struct
import six
import re


def args(*params):
    """Constructs a dict from a list of arguments for sending a CBOR command.
    None elements will be omitted.

    :param params: Arguments, in order, to add to the command.
    :return: The input parameters as a dict.
    """
    return dict((i, v) for i, v in enumerate(params, 1) if v is not None)


def hexstr(bs):
    """Formats a byte string as a human readable hex string.

    :param bs: The bytes to format.
    :return: A readable string representation of the input.
    """
    return "h'%s'" % b2a_hex(bs).decode()


class Info(bytes):
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

    @unique
    class KEY(IntEnum):
        VERSIONS = 0x01
        EXTENSIONS = 0x02
        AAGUID = 0x03
        OPTIONS = 0x04
        MAX_MSG_SIZE = 0x05
        PIN_UV_PROTOCOLS = 0x06
        MAX_CREDS_IN_LIST = 0x07
        MAX_CRED_ID_LENGTH = 0x08
        TRANSPORTS = 0x09
        ALGORITHMS = 0x0A
        MAX_LARGE_BLOB = 0x0B
        FORCE_PIN_CHANGE = 0x0C
        MIN_PIN_LENGTH = 0x0D
        FIRMWARE_VERSION = 0x0E
        MAX_CRED_BLOB_LENGTH = 0x0F
        MAX_RPIDS_FOR_MIN_PIN = 0x10
        PREFERRED_PLATFORM_UV_ATTEMPTS = 0x11
        UV_MODALITY = 0x12
        CERTIFICATIONS = 0x13
        REMAINING_DISC_CREDS = 0x14

        @classmethod
        def get(cls, key):
            try:
                return cls(key)
            except ValueError:
                return key

        def __repr__(self):
            return "<%s: 0x%02X>" % (self.name, self)

    def __init__(self, _):
        super(Info, self).__init__()

        data = dict((Info.KEY.get(k), v) for (k, v) in cbor.decode(self).items())
        self.versions = data[Info.KEY.VERSIONS]
        self.extensions = data.get(Info.KEY.EXTENSIONS, [])
        self.aaguid = data[Info.KEY.AAGUID]
        self.options = data.get(Info.KEY.OPTIONS, {})
        self.max_msg_size = data.get(Info.KEY.MAX_MSG_SIZE, 1024)
        self.pin_uv_protocols = data.get(Info.KEY.PIN_UV_PROTOCOLS, [])
        self.max_creds_in_list = data.get(Info.KEY.MAX_CREDS_IN_LIST)
        self.max_cred_id_length = data.get(Info.KEY.MAX_CRED_ID_LENGTH)
        self.transports = data.get(Info.KEY.TRANSPORTS, [])
        self.algorithms = data.get(Info.KEY.ALGORITHMS)
        self.max_large_blob = data.get(Info.KEY.MAX_LARGE_BLOB)
        self.force_pin_change = data.get(Info.KEY.FORCE_PIN_CHANGE, False)
        self.min_pin_length = data.get(Info.KEY.MIN_PIN_LENGTH, 4)
        self.firmware_version = data.get(Info.KEY.FIRMWARE_VERSION)
        self.max_cred_blob_length = data.get(Info.KEY.MAX_CRED_BLOB_LENGTH)
        self.max_rpids_for_min_pin = data.get(Info.KEY.MAX_RPIDS_FOR_MIN_PIN, 0)
        self.uv_modality = data.get(Info.KEY.UV_MODALITY)
        self.certifications = data.get(Info.KEY.CERTIFICATIONS, {})
        self.remaining_disc_creds = data.get(Info.KEY.REMAINING_DISC_CREDS)
        self.data = data

    def __repr__(self):
        return "%s" % self.data

    def __str__(self):
        return self.__repr__()

    @classmethod
    def create(
        cls,
        versions,
        extensions=None,
        aaguid=b"\0" * 16,
        options=None,
        max_msg_size=None,
        pin_uv_protocols=None,
        max_creds_in_list=None,
        max_cred_id_length=None,
        transports=None,
        algorithms=None,
    ):
        """Create an Info by providing its components.

        See class docstring for parameter descriptions.
        """
        return cls(
            cbor.encode(
                args(
                    versions,
                    extensions,
                    aaguid,
                    options,
                    max_msg_size,
                    pin_uv_protocols,
                    max_creds_in_list,
                    max_cred_id_length,
                    transports,
                    algorithms,
                )
            )
        )


class AttestedCredentialData(bytes):
    """Binary encoding of the attested credential data.

    :param _: The binary representation of the attested credential data.
    :ivar aaguid: The AAGUID of the authenticator.
    :ivar credential_id: The binary ID of the credential.
    :ivar public_key: The public key of the credential.
    """

    def __init__(self, _):
        super(AttestedCredentialData, self).__init__()

        parsed = AttestedCredentialData.parse(self)
        self.aaguid = parsed[0]
        self.credential_id = parsed[1]
        self.public_key = parsed[2]
        if parsed[3]:
            raise ValueError("Wrong length")

    def __repr__(self):
        return (
            "AttestedCredentialData(aaguid: %s, credential_id: %s, " "public_key: %s"
        ) % (hexstr(self.aaguid), hexstr(self.credential_id), self.public_key)

    def __str__(self):
        return self.__repr__()

    @staticmethod
    def parse(data):
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
    def create(cls, aaguid, credential_id, public_key):
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
    def unpack_from(cls, data):
        """Unpack an AttestedCredentialData from a byte string, returning it and
        any remaining data.

        :param data: A binary string containing an attested credential data.
        :return: The parsed AttestedCredentialData, and any remaining data from
            the input.
        """
        parts = cls.parse(data)
        return cls.create(*parts[:-1]), parts[-1]

    @classmethod
    def from_ctap1(cls, key_handle, public_key):
        """Create an AttestatedCredentialData from a CTAP1 RegistrationData
        instance.

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
    class FLAG(IntEnum):
        """Authenticator data flags

        See https://www.w3.org/TR/webauthn/#sec-authenticator-data for details
        """

        USER_PRESENT = 0x01
        USER_VERIFIED = 0x04
        ATTESTED = 0x40
        EXTENSION_DATA = 0x80

    def __init__(self, _):
        super(AuthenticatorData, self).__init__()

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

    @classmethod
    def create(cls, rp_id_hash, flags, counter, credential_data=b"", extensions=None):
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

    def is_user_present(self):
        """Return true if the User Present flag is set.

        :return: True if User Present is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAG.USER_PRESENT)

    def is_user_verified(self):
        """Return true if the User Verified flag is set.

        :return: True if User Verified is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAG.USER_VERIFIED)

    def is_attested(self):
        """Return true if the Attested credential data flag is set.

        :return: True if Attested credential data is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAG.ATTESTED)

    def has_extension_data(self):
        """Return true if the Extenstion data flag is set.

        :return: True if Extenstion data is set, False otherwise.
        :rtype: bool
        """
        return bool(self.flags & AuthenticatorData.FLAG.EXTENSION_DATA)

    def __repr__(self):
        r = "AuthenticatorData(rp_id_hash: %s, flags: 0x%02x, counter: %d" % (
            hexstr(self.rp_id_hash),
            self.flags,
            self.counter,
        )
        if self.credential_data:
            r += ", credential_data: %s" % self.credential_data
        if self.extensions:
            r += ", extensions: %s" % self.extensions
        return r + ")"

    def __str__(self):
        return self.__repr__()


class AttestationObject(bytes):
    """Binary CBOR encoded attestation object.

    :param _: The binary representation of the attestation object.
    :type _: bytes
    :ivar fmt: The type of attestation used.
    :type fmt: str
    :ivar auth_data: The attested authenticator data.
    :type auth_data: AuthenticatorData
    :ivar att_statement: The attestation statement.
    :type att_statement: Dict[str, Any]
    :ivar data: The AttestationObject members, in the form of a dict.
    :type data: Dict[AttestationObject.KEY, Any]
    """

    @unique
    class KEY(IntEnum):
        FMT = 1
        AUTH_DATA = 2
        ATT_STMT = 3
        EP_ATT = 4
        LARGE_BLOB_KEY = 5

        @classmethod
        def for_key(cls, key):
            """Get an AttestationObject.KEY by number or by name, using the
            numeric ID or the Webauthn key string.

            :param key: The numeric key value, or the string name of a member.
            :type key: Union[str, int]
            :return: The KEY corresponding to the input.
            :rtype: AttestationObject.KEY
            """
            if isinstance(key, int):
                return cls(key)
            name = re.sub("([a-z])([A-Z])", r"\1_\2", key).upper()
            return getattr(cls, name)

        @property
        def string_key(self):
            """Get the string used for this key in the Webauthn specification.

            :return: The Webauthn string used for a key.
            :rtype: str
            """
            value = "".join(w.capitalize() for w in self.name.split("_"))
            return value[0].lower() + value[1:]

    def __init__(self, _):
        super(AttestationObject, self).__init__()

        data = dict(
            (AttestationObject.KEY.for_key(k), v)
            for (k, v) in cbor.decode(self).items()
        )
        self.fmt = data[AttestationObject.KEY.FMT]
        self.auth_data = AuthenticatorData(data[AttestationObject.KEY.AUTH_DATA])
        data[AttestationObject.KEY.AUTH_DATA] = self.auth_data
        self.att_statement = data[AttestationObject.KEY.ATT_STMT]
        self.ep_att = data.get(AttestationObject.KEY.EP_ATT)
        self.large_blob_key = data.get(AttestationObject.KEY.LARGE_BLOB_KEY)
        self.data = data

    def __repr__(self):
        return (
            "AttestationObject(fmt: %r, auth_data: %r, att_statement: %r, "
            "ep_attr: %r, large_blob_key: %r)"
        ) % (
            self.fmt,
            self.auth_data,
            self.att_statement,
            self.ep_att,
            self.large_blob_key,
        )

    def __str__(self):
        return self.__repr__()

    @classmethod
    def create(cls, fmt, auth_data, att_stmt):
        """Create an AttestationObject instance.

        :param fmt: The type of attestation used.
        :type fmt: str
        :param auth_data: Binary representation of the authenticator data.
        :type auth_data: bytes
        :param att_stmt: The attestation statement.
        :type att_stmt: dict
        :return: The attestation object.
        :rtype: AttestationObject
        """
        return cls(cbor.encode(args(fmt, auth_data, att_stmt)))

    @classmethod
    def from_ctap1(cls, app_param, registration):
        """Create an AttestationObject from a CTAP1 RegistrationData instance.

        :param app_param: SHA256 hash of the RP ID used for the CTAP1 request.
        :type app_param: bytes
        :param registration: The CTAP1 registration data.
        :type registration: RegistrationData
        :return: The attestation object, using the "fido-u2f" format.
        :rtype: AttestationObject
        """
        return cls.create(
            FidoU2FAttestation.FORMAT,
            AuthenticatorData.create(
                app_param,
                0x41,
                0,
                AttestedCredentialData.from_ctap1(
                    registration.key_handle, registration.public_key
                ),
            ),
            {  # att_statement
                "x5c": [registration.certificate],
                "sig": registration.signature,
            },
        )

    def with_int_keys(self):
        """Get a copy of this AttestationObject, using CTAP2 integer values as
        map keys in the CBOR representation.

        :return: The attestation object, using int keys.
        :rtype: AttestationObject
        """
        return AttestationObject(cbor.encode(self.data))

    def with_string_keys(self):
        """Get a copy of this AttestationObject, using Webauthn string values as
        map keys in the CBOR representation.

        :return: The attestation object, using str keys.
        :rtype: AttestationObject
        """
        return AttestationObject(
            cbor.encode(dict((k.string_key, v) for k, v in self.data.items()))
        )


class AssertionResponse(bytes):
    """Binary CBOR encoded assertion response.

    :param _: The binary representation of the assertion response.
    :ivar credential: The credential used for the assertion.
    :ivar auth_data: The authenticator data part of the response.
    :ivar signature: The digital signature of the assertion.
    :ivar user: The user data of the credential.
    :ivar number_of_credentials: The total number of responses available
        (only set for the first response, if > 1).
    """

    @unique
    class KEY(IntEnum):
        CREDENTIAL = 1
        AUTH_DATA = 2
        SIGNATURE = 3
        USER = 4
        N_CREDS = 5
        USER_SELECTED = 6
        LARGE_BLOB_KEY = 7

    def __init__(self, _):
        super(AssertionResponse, self).__init__()

        data = dict(
            (AssertionResponse.KEY(k), v) for (k, v) in cbor.decode(self).items()
        )
        self.credential = data.get(AssertionResponse.KEY.CREDENTIAL)
        self.auth_data = AuthenticatorData(data[AssertionResponse.KEY.AUTH_DATA])
        self.signature = data[AssertionResponse.KEY.SIGNATURE]
        self.user = data.get(AssertionResponse.KEY.USER)
        self.number_of_credentials = data.get(AssertionResponse.KEY.N_CREDS)
        self.user_selected = data.get(AssertionResponse.KEY.USER_SELECTED, False)
        self.large_blob_key = data.get(AssertionResponse.KEY.LARGE_BLOB_KEY)
        self.data = data

    def __repr__(self):
        r = "AssertionResponse(credential: %r, auth_data: %r, signature: %s" % (
            self.credential,
            self.auth_data,
            hexstr(self.signature),
        )
        if self.user:
            r += ", user: %s" % self.user
        if self.number_of_credentials is not None:
            r += ", number_of_credentials: %d" % self.number_of_credentials
        return r + ")"

    def __str__(self):
        return self.__repr__()

    def verify(self, client_param, public_key):
        """Verify the digital signature of the response with regard to the
        client_param, using the given public key.

        :param client_param: SHA256 hash of the ClientData used for the request.
        :param public_key: The public key of the credential, to verify.
        """
        public_key.verify(self.auth_data + client_param, self.signature)

    @classmethod
    def create(cls, credential, auth_data, signature, user=None, n_creds=None):
        """Create an AssertionResponse instance.

        :param credential: The credential used for the response.
        :param auth_data: The binary encoded authenticator data.
        :param signature: The digital signature of the response.
        :param user: The user data of the credential, if any.
        :param n_creds: The number of responses available.
        :return: The assertion response.
        """
        return cls(cbor.encode(args(credential, auth_data, signature, user, n_creds)))

    @classmethod
    def from_ctap1(cls, app_param, credential, authentication):
        """Create an AssertionResponse from a CTAP1 SignatureData instance.

        :param app_param: SHA256 hash of the RP ID used for the CTAP1 request.
        :param credential: Credential used for the CTAP1 request (from the
            allowList).
        :param authentication: The CTAP1 signature data.
        :return: The assertion response.
        """
        return cls.create(
            credential,
            AuthenticatorData.create(
                app_param, authentication.user_presence & 0x01, authentication.counter
            ),
            authentication.signature,
        )


class Ctap2(object):
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

    def __init__(self, device, strict_cbor=True):
        if not device.capabilities & CAPABILITY.CBOR:
            raise ValueError("Device does not support CTAP2.")
        self.device = device
        self._strict_cbor = strict_cbor
        self._info = self.get_info()

    @property
    def info(self):
        """Get a cached Info object which can be used to determine capabilities.

        :rtype: Info
        :return: The response of calling GetAuthenticatorInfo.
        """
        return self._info

    def send_cbor(
        self, cmd, data=None, event=None, parse=cbor.decode, on_keepalive=None
    ):
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
        status = six.indexbytes(response, 0)
        if status != 0x00:
            raise CtapError(status)
        if len(response) == 1:
            return None
        enc = response[1:]
        if self._strict_cbor:
            expected = cbor.encode(cbor.decode(enc))
            if expected != enc:
                enc_h = b2a_hex(enc)
                exp_h = b2a_hex(expected)
                raise ValueError(
                    "Non-canonical CBOR from Authenticator.\n"
                    "Got: {}\n".format(enc_h) + "Expected: {}".format(exp_h)
                )
        return parse(enc)

    def get_info(self):
        """CTAP2 getInfo command.

        :return: Information about the authenticator.
        """
        return self.send_cbor(Ctap2.CMD.GET_INFO, parse=Info)

    def client_pin(
        self,
        pin_uv_protocol,
        sub_cmd,
        key_agreement=None,
        pin_uv_param=None,
        new_pin_enc=None,
        pin_hash_enc=None,
        permissions=None,
        permissions_rpid=None,
        event=None,
        on_keepalive=None,
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
        :param event: Optional threading.Event used to cancel the request.
        :param on_keepalive: Optional callback function to handle keep-alive
            messages from the authenticator.
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
            event=event,
            on_keepalive=on_keepalive,
        )

    def reset(self, event=None, on_keepalive=None):
        """CTAP2 reset command, erases all credentials and PIN.

        :param event: Optional threading.Event object used to cancel the request.
        :param on_keepalive: Optional callback function to handle keep-alive
            messages from the authenticator.
        """
        self.send_cbor(Ctap2.CMD.RESET, event=event, on_keepalive=on_keepalive)

    def make_credential(
        self,
        client_data_hash,
        rp,
        user,
        key_params,
        exclude_list=None,
        extensions=None,
        options=None,
        pin_uv_param=None,
        pin_uv_protocol=None,
        event=None,
        on_keepalive=None,
    ):
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
        return self.send_cbor(
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
            AttestationObject,
            on_keepalive,
        )

    def get_assertion(
        self,
        rp_id,
        client_data_hash,
        allow_list=None,
        extensions=None,
        options=None,
        pin_uv_param=None,
        pin_uv_protocol=None,
        event=None,
        on_keepalive=None,
    ):
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
        return self.send_cbor(
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
            AssertionResponse,
            on_keepalive,
        )

    def get_next_assertion(self):
        """CTAP2 getNextAssertion command.

        :return: The next available assertion response.
        """
        return self.send_cbor(Ctap2.CMD.GET_NEXT_ASSERTION, parse=AssertionResponse)

    def get_assertions(self, *args, **kwargs):
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
        self, sub_cmd, sub_cmd_params=None, pin_uv_protocol=None, pin_uv_param=None
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
            cmd, args(sub_cmd, sub_cmd_params, pin_uv_protocol, pin_uv_param),
        )

    def bio_enrollment(
        self,
        modality=None,
        sub_cmd=None,
        sub_cmd_params=None,
        pin_uv_protocol=None,
        pin_uv_param=None,
        get_modality=None,
        event=None,
        on_keepalive=None,
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

    def selection(self, event=None, on_keepalive=None):
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
        offset,
        get=None,
        set=None,
        length=None,
        pin_uv_param=None,
        pin_uv_protocol=None,
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
        self, sub_cmd, sub_cmd_params=None, pin_uv_protocol=None, pin_uv_param=None
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
