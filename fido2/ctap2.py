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

from . import cbor
from .ctap import CtapError
from .cose import CoseKey, ES256
from .hid import CTAPHID, CAPABILITY
from .utils import ByteBuffer, sha256, hmac_sha256, bytes2int, int2bytes
from .attestation import FidoU2FAttestation

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

        @classmethod
        def get(cls, key):
            try:
                return cls(key)
            except ValueError:
                return key

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
        self.data = data

    def __repr__(self):
        r = "Info(versions: %r" % self.versions
        if self.extensions:
            r += ", extensions: %r" % self.extensions
        r += ", aaguid: %s" % hexstr(self.aaguid)
        if self.options:
            r += ", options: %r" % self.options
        r += ", max_message_size: %d" % self.max_msg_size
        if self.pin_uv_protocols:
            r += ", pin_uv_protocols: %r" % self.pin_uv_protocols
        if self.max_creds_in_list:
            r += ", max_credential_count_in_list: %d" % self.max_creds_in_list
        if self.max_cred_id_length:
            r += ", max_credential_id_length: %d" % self.max_cred_id_length
        if self.transports:
            r += ", transports: %r" % self.transports
        if self.algorithms:
            r += ", algorithms: %r" % self.algorithms
        return r + ")"

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
        self.data = data

    def __repr__(self):
        return "AttestationObject(fmt: %r, auth_data: %r, att_statement: %r)" % (
            self.fmt,
            self.auth_data,
            self.att_statement,
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


class CTAP2(object):
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
        # 0x40 is the command byte for bio enrollment preview
        BIO_ENROLLMENT = 0x40  # 0x09
        # 0x41 is the command byte for credmgmt preview
        CREDENTIAL_MGMT = 0x41

    def __init__(self, device, strict_cbor=True):
        if not device.capabilities & CAPABILITY.CBOR:
            raise ValueError("Device does not support CTAP2.")
        self.device = device
        self._strict_cbor = strict_cbor

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
            CTAP2.CMD.MAKE_CREDENTIAL,
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
        :param on_keepalive: Optional callback function to handle keep-alive
            messages from the authenticator.
        :return: The new assertion.
        """
        return self.send_cbor(
            CTAP2.CMD.GET_ASSERTION,
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

    def get_info(self):
        """CTAP2 getInfo command.

        :return: Information about the authenticator.
        """
        return self.send_cbor(CTAP2.CMD.GET_INFO, parse=Info)

    def client_pin(
        self,
        pin_uv_protocol,
        sub_cmd,
        key_agreement=None,
        pin_uv_param=None,
        new_pin_enc=None,
        pin_hash_enc=None,
        min_pin_len=None,
        min_pin_len_rpids=None,
        permissions=None,
        permissions_rpid=None,
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
        :param min_pin_len: The minPinLength parameter.
        :param min_pin_len_rpids: The minPinLengthRPIDs parameter.
        :param permissions: The permissions parameter.
        :param permissions_rpid: The permissions RPID parameter.
        :return: The response of the command, decoded.
        """
        return self.send_cbor(
            CTAP2.CMD.CLIENT_PIN,
            args(
                pin_uv_protocol,
                sub_cmd,
                key_agreement,
                pin_uv_param,
                new_pin_enc,
                pin_hash_enc,
                min_pin_len,
                min_pin_len_rpids,
                permissions,
                permissions_rpid,
            ),
        )

    def reset(self, event=None, on_keepalive=None):
        """CTAP2 reset command, erases all credentials and PIN.

        :param event: Optional threading.Event object used to cancel the request.
        :param on_keepalive: Optional callback function to handle keep-alive
            messages from the authenticator.
        """
        self.send_cbor(CTAP2.CMD.RESET, event=event, on_keepalive=on_keepalive)

    def get_next_assertion(self):
        """CTAP2 getNextAssertion command.

        :return: The next available assertion response.
        """
        return self.send_cbor(CTAP2.CMD.GET_NEXT_ASSERTION, parse=AssertionResponse)

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
        return self.send_cbor(
            CTAP2.CMD.CREDENTIAL_MGMT,
            args(sub_cmd, sub_cmd_params, pin_uv_protocol, pin_uv_param),
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
        return self.send_cbor(
            CTAP2.CMD.BIO_ENROLLMENT,
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


def _pad_pin(pin):
    if not isinstance(pin, six.string_types):
        raise ValueError("PIN of wrong type, expecting %s" % six.string_types)
    if len(pin) < 4:
        raise ValueError("PIN must be >= 4 characters")
    pin = pin.encode("utf8").ljust(64, b"\0")
    pin += b"\0" * (-(len(pin) - 16) % 16)
    if len(pin) > 255:
        raise ValueError("PIN must be <= 255 bytes")
    return pin


class PinProtocolV1(object):
    """Implementation of the CTAP2 PIN/UV protocol v1.

    :param ctap: An instance of a CTAP2 object.
    :cvar VERSION: The version number of the PIV/UV protocol.
    :cvar IV: An all-zero IV used for some cryptographic operations.
    """

    VERSION = 1
    IV = b"\x00" * 16

    def encapsulate(self, peer_cose_key):
        be = default_backend()
        sk = ec.generate_private_key(ec.SECP256R1(), be)
        pn = sk.public_key().public_numbers()
        key_agreement = {
            1: 2,
            3: -25,  # Per the spec, "although this is NOT the algorithm actually used"
            -1: 1,
            -2: int2bytes(pn.x, 32),
            -3: int2bytes(pn.y, 32),
        }

        x = bytes2int(peer_cose_key[-2])
        y = bytes2int(peer_cose_key[-3])
        pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(be)
        shared_secret = sha256(sk.exchange(ec.ECDH(), pk))  # x-coordinate, 32b
        return key_agreement, shared_secret

    def _get_cipher(self, secret):
        be = default_backend()
        return Cipher(algorithms.AES(secret), modes.CBC(PinProtocolV1.IV), be)

    def encrypt(self, key, plaintext):
        cipher = self._get_cipher(key)
        enc = cipher.encryptor()
        return enc.update(plaintext) + enc.finalize()

    def decrypt(self, key, ciphertext):
        cipher = self._get_cipher(key)
        dec = cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()

    def authenticate(self, key, message):
        return hmac_sha256(key, message)[:16]


class ClientPin(object):
    """Implementation of the CTAP2 Client PIN API.

    :param ctap: An instance of a CTAP2 object.
    :param protocol: An instance of a PinUvAuthProtocol object.
    """

    @unique
    class CMD(IntEnum):
        GET_PIN_RETRIES = 0x01
        GET_KEY_AGREEMENT = 0x02
        SET_PIN = 0x03
        CHANGE_PIN = 0x04
        GET_TOKEN_USING_PIN = 0x05
        GET_TOKEN_USING_UV = 0x06
        GET_UV_RETRIES = 0x07

    @unique
    class RESULT(IntEnum):
        KEY_AGREEMENT = 0x01
        PIN_UV_TOKEN = 0x02
        PIN_RETRIES = 0x03
        POWER_CYCLE_STATE = 0x04
        UV_RETRIES = 0x05

    def __init__(self, ctap, protocol):
        self.ctap = ctap
        self.protocol = protocol

    def _get_shared_secret(self):
        resp = self.ctap.client_pin(
            self.protocol.VERSION, ClientPin.CMD.GET_KEY_AGREEMENT
        )
        pk = resp[ClientPin.RESULT.KEY_AGREEMENT]

        return self.protocol.encapsulate(pk)

    def get_pin_token(self, pin):
        """Get a PIN/UV token from the authenticator using PIN.

        :param pin: The PIN of the authenticator.
        :return: A PIN/UV token.
        """
        key_agreement, shared_secret = self._get_shared_secret()

        pin_hash = sha256(pin.encode())[:16]
        pin_hash_enc = self.protocol.encrypt(shared_secret, pin_hash)

        resp = self.ctap.client_pin(
            self.protocol.VERSION,
            ClientPin.CMD.GET_TOKEN_USING_PIN,
            key_agreement=key_agreement,
            pin_hash_enc=pin_hash_enc,
        )
        pin_token_enc = resp[ClientPin.RESULT.PIN_UV_TOKEN]
        return self.protocol.decrypt(shared_secret, pin_token_enc)

    def get_uv_token(self, permissions, permissions_rpid):
        """Get a PIN/UV token from the authenticator using built-in UV.

        :param permissions: The permissions to associate with the token.
        :param permissions_rpid: The permissions RPID to associate with the token.
        :return: A PIN/UV token.
        """
        key_agreement, shared_secret = self._get_shared_secret()

        resp = self.ctap.client_pin(
            self.protocol.VERSION,
            ClientPin.CMD.GET_TOKEN_USING_UV,
            key_agreement=key_agreement,
            permissions=permissions,
            permissions_rpid=permissions_rpid,
        )

        pin_token_enc = resp[ClientPin.RESULT.PIN_UV_TOKEN]
        return self.protocol.decrypt(shared_secret, pin_token_enc)

    def get_pin_retries(self):
        """Get the number of PIN retries remaining.

        :return: A tuple of the number of PIN attempts remaining until the
        authenticator is locked, and the power cycle state, if available.
        """
        resp = self.ctap.client_pin(
            self.protocol.VERSION, ClientPin.CMD.GET_PIN_RETRIES
        )
        return (
            resp[ClientPin.RESULT.PIN_RETRIES],
            resp.get(ClientPin.RESULT.POWER_CYCLE_STATE),
        )

    def get_uv_retries(self):
        """Get the number of UV retries remaining.

        :return: A tuple of the number of UV attempts remaining until the
        authenticator is locked, and the power cycle state, if available.
        """
        resp = self.ctap.client_pin(self.protocol.VERSION, ClientPin.CMD.GET_UV_RETRIES)
        return (
            resp[ClientPin.RESULT.UV_RETRIES],
            resp.get(ClientPin.RESULT.POWER_CYCLE_STATE),
        )

    def set_pin(self, pin):
        """Set the PIN of the autenticator.

        This only works when no PIN is set. To change the PIN when set, use
        change_pin.

        :param pin: A PIN to set.
        """
        pin = _pad_pin(pin)
        key_agreement, shared_secret = self._get_shared_secret()

        pin_enc = self.protocol.encrypt(shared_secret, pin)
        pin_uv_param = self.protocol.authenticate(shared_secret, pin_enc)
        self.ctap.client_pin(
            self.protocol.VERSION,
            ClientPin.CMD.SET_PIN,
            key_agreement=key_agreement,
            new_pin_enc=pin_enc,
            pin_uv_param=pin_uv_param,
        )

    def change_pin(self, old_pin, new_pin):
        """Change the PIN of the authenticator.

        This only works when a PIN is already set. If no PIN is set, use
        set_pin.

        :param old_pin: The currently set PIN.
        :param new_pin: The new PIN to set.
        """
        new_pin = _pad_pin(new_pin)
        key_agreement, shared_secret = self._get_shared_secret()

        pin_hash = sha256(old_pin.encode())[:16]
        pin_hash_enc = self.protocol.encrypt(shared_secret, pin_hash)
        new_pin_enc = self.protocol.encrypt(shared_secret, new_pin)
        pin_uv_param = self.protocol.authenticate(
            shared_secret, new_pin_enc + pin_hash_enc
        )
        self.ctap.client_pin(
            self.protocol.VERSION,
            ClientPin.CMD.CHANGE_PIN,
            key_agreement=key_agreement,
            pin_hash_enc=pin_hash_enc,
            new_pin_enc=new_pin_enc,
            pin_uv_param=pin_uv_param,
        )


class CredentialManagement(object):
    """Implementation of a draft specification of the Credential Management API.
    WARNING: This specification is not final and this class is likely to change.

    :param ctap: An instance of a CTAP2 object.
    :param pin_uv_protocol: An instance of a PinUvAuthProtocol.
    :param pin_uv_token: A valid PIN/UV Auth Token for the current CTAP session.
    """

    @unique
    class CMD(IntEnum):
        GET_CREDS_METADATA = 0x01
        ENUMERATE_RPS_BEGIN = 0x02
        ENUMERATE_RPS_NEXT = 0x03
        ENUMERATE_CREDS_BEGIN = 0x04
        ENUMERATE_CREDS_NEXT = 0x05
        DELETE_CREDENTIAL = 0x06

    @unique
    class PARAM(IntEnum):
        RP_ID_HASH = 0x01
        CREDENTIAL_ID = 0x02

    @unique
    class RESULT(IntEnum):
        EXISTING_CRED_COUNT = 0x01
        MAX_REMAINING_COUNT = 0x02
        RP = 0x03
        RP_ID_HASH = 0x04
        TOTAL_RPS = 0x05
        USER = 0x06
        CREDENTIAL_ID = 0x07
        PUBLIC_KEY = 0x08
        TOTAL_CREDENTIALS = 0x09
        CRED_PROTECT = 0x0A

    def __init__(self, ctap, pin_uv_protocol, pin_uv_token):
        self.ctap = ctap
        self.pin_uv_protocol = pin_uv_protocol
        self.pin_uv_token = pin_uv_token

    def _call(self, sub_cmd, params=None, auth=True):
        kwargs = {"sub_cmd": sub_cmd, "sub_cmd_params": params}
        if auth:
            msg = struct.pack(">B", sub_cmd)
            if params is not None:
                msg += cbor.encode(params)
            kwargs["pin_uv_protocol"] = self.pin_uv_protocol.VERSION
            kwargs["pin_uv_param"] = self.pin_uv_protocol.authenticate(
                self.pin_uv_token, msg
            )
        return self.ctap.credential_mgmt(**kwargs)

    def get_metadata(self):
        """Get credentials metadata.

        This returns the existing resident credentials count, and the max
        possible number of remaining resident credentials (the actual number of
        remaining credentials may depend on algorithm choice, etc).

        :return: A dict containing EXISTING_CRED_COUNT, and MAX_REMAINING_COUNT.
        """
        return self._call(CredentialManagement.CMD.GET_CREDS_METADATA)

    def enumerate_rps_begin(self):
        """Start enumeration of RP entities of resident credentials.

        This will begin enumeration of stored RP entities, returning the first
        entity, as well as a count of the total number of entities stored.

        :return: A dict containing RP, RP_ID_HASH, and TOTAL_RPS.
        """
        return self._call(CredentialManagement.CMD.ENUMERATE_RPS_BEGIN)

    def enumerate_rps_next(self):
        """Get the next RP entity stored.

        This continues enumeration of stored RP entities, returning the next
        entity.

        :return: A dict containing RP, and RP_ID_HASH.
        """
        return self._call(CredentialManagement.CMD.ENUMERATE_RPS_NEXT, auth=False)

    def enumerate_rps(self):
        """Convenience method to enumerate all RPs.

        See enumerate_rps_begin and enumerate_rps_next for details.
        """
        first = self.enumerate_rps_begin()
        n_rps = first[CredentialManagement.RESULT.TOTAL_RPS]
        if n_rps == 0:
            return []
        rest = [self.enumerate_rps_next() for _ in range(1, n_rps)]
        return [first] + rest

    def enumerate_creds_begin(self, rp_id_hash):
        """Start enumeration of resident credentials.

        This will begin enumeration of resident credentials for a given RP,
        returning the first credential, as well as a count of the total number
        of resident credentials stored for the given RP.

        :param rp_id_hash: SHA256 hash of the RP ID.
        :return: A dict containing USER, CREDENTIAL_ID, PUBLIC_KEY, and
            TOTAL_CREDENTIALS.
        """
        return self._call(
            CredentialManagement.CMD.ENUMERATE_CREDS_BEGIN,
            {CredentialManagement.PARAM.RP_ID_HASH: rp_id_hash},
        )

    def enumerate_creds_next(self):
        """Get the next resident credential stored.

        This continues enumeration of resident credentials, returning the next
        credential.

        :return: A dict containing USER, CREDENTIAL_ID, and PUBLIC_KEY.
        """
        return self._call(CredentialManagement.CMD.ENUMERATE_CREDS_NEXT, auth=False)

    def enumerate_creds(self, *args, **kwargs):
        """Convenience method to enumerate all resident credentials for an RP.

        See enumerate_creds_begin and enumerate_creds_next for details.
        """
        try:
            first = self.enumerate_creds_begin(*args, **kwargs)
        except CtapError as e:
            if e.code == CtapError.ERR.NO_CREDENTIALS:
                return []
            raise  # Other error
        rest = [
            self.enumerate_creds_next()
            for _ in range(
                1, first.get(CredentialManagement.RESULT.TOTAL_CREDENTIALS, 1)
            )
        ]
        return [first] + rest

    def delete_cred(self, cred_id):
        """Delete a resident credential.

        :param cred_id: The ID of the credential to delete.
        """
        return self._call(
            CredentialManagement.CMD.DELETE_CREDENTIAL,
            {CredentialManagement.PARAM.CREDENTIAL_ID: cred_id},
        )


class BioEnrollment(object):
    @unique
    class RESULT(IntEnum):
        MODALITY = 0x01
        FINGERPRINT_KIND = 0x02
        MAX_SAMPLES_REQUIRED = 0x03
        TEMPLATE_ID = 0x04
        LAST_SAMPLE_STATUS = 0x05
        REMAINING_SAMPLES = 0x06
        TEMPLATE_INFOS = 0x07

    @unique
    class TEMPLATE_INFO(IntEnum):
        ID = 0x01
        NAME = 0x02

    @unique
    class MODALITY(IntEnum):
        FINGERPRINT = 0x01

    def __init__(self, ctap, modality):
        self.ctap = ctap
        self.modality = self.get_modality()
        if modality != self.modality:
            raise ValueError("Device does not support {%s}".format(modality))

    def get_modality(self):
        """Get bio modality.

        :return: The type of modality supported by the authenticator.
        """
        return self.ctap.bio_enrollment(get_modality=True)[
            BioEnrollment.RESULT.MODALITY
        ]


class CaptureError(Exception):
    def __init__(self, code):
        self.code = code
        super(CaptureError, self).__init__("Fingerprint capture error: %s" % code)


class FPEnrollmentContext(object):
    """Helper object to perform fingerprint enrollment.

    :param bio: An instance of FPBioEnrollment.
    :param timeout: Optional timeout for fingerprint captures (ms).
    """

    def __init__(self, bio, timeout=None):
        self._bio = bio
        self.timeout = timeout
        self.template_id = None

    def capture(self, event=None, on_keepalive=None):
        """Capture a fingerprint sample.

        This call will block for up to timeout milliseconds (or indefinitely, if
        timeout not specified) waiting for the user to scan their fingerprint to
        collect one sample.

        :return: None, if more samples are needed, or the template ID if enrollment is
            completed.
        """
        if self.template_id is None:
            self.template_id, status, remaining = self._bio.enroll_begin(
                self.timeout, event, on_keepalive
            )
        else:
            status, remaining = self._bio.enroll_capture_next(
                self.template_id, self.timeout, event, on_keepalive
            )
        if status != FPBioEnrollment.FEEDBACK.FP_GOOD:
            raise CaptureError(status)
        if remaining == 0:
            return self.template_id
        return None

    def cancel(self):
        """Cancels ongoing enrollment."""
        self._bio.enroll_cancel()
        self.template_id = None


class FPBioEnrollment(BioEnrollment):
    """Implementation of a draft specification of the bio enrollment API.
    WARNING: This specification is not final and this class is likely to change.

    NOTE: The get_fingerprint_sensor_info method does not require authentication, and
    can be used by setting pin_uv_protocol and pin_uv_token to None.

    :param ctap: An instance of a CTAP2 object.
    :param pin_uv_protocol: The PIN/UV protocol version used.
    :param pin_uv_token: A valid PIN/UV Auth Token for the current CTAP session.
    """

    @unique
    class CMD(IntEnum):
        ENROLL_BEGIN = 0x01
        ENROLL_CAPTURE_NEXT = 0x02
        ENROLL_CANCEL = 0x03
        ENUMERATE_ENROLLMENTS = 0x04
        SET_NAME = 0x05
        REMOVE_ENROLLMENT = 0x06
        GET_SENSOR_INFO = 0x07

    @unique
    class PARAM(IntEnum):
        TEMPLATE_ID = 0x01
        TEMPLATE_NAME = 0x02
        TIMEOUT_MS = 0x03

    @unique
    class FEEDBACK(IntEnum):
        FP_GOOD = 0x00
        FP_TOO_HIGH = 0x01
        FP_TOO_LOW = 0x02
        FP_TOO_LEFT = 0x03
        FP_TOO_RIGHT = 0x04
        FP_TOO_FAST = 0x05
        FP_TOO_SLOW = 0x06
        FP_POOR_QUALITY = 0x07
        FP_TOO_SKEWED = 0x08
        FP_TOO_SHORT = 0x09
        FP_MERGE_FAILURE = 0x0A
        FP_EXISTS = 0x0B
        FP_DATABASE_FULL = 0x0C
        NO_USER_ACTIVITY = 0x0D
        NO_UP_TRANSITION = 0x0E

        def __str__(self):
            return "0x%02X - %s" % (self.value, self.name)

    def __init__(self, ctap, pin_uv_protocol, pin_uv_token):
        super(FPBioEnrollment, self).__init__(ctap, BioEnrollment.MODALITY.FINGERPRINT)
        self.pin_uv_protocol = pin_uv_protocol
        self.pin_uv_token = pin_uv_token

    def _call(self, sub_cmd, params=None, auth=True, event=None, on_keepalive=None):
        if params is not None:
            params = {k: v for k, v in params.items() if v is not None}
        kwargs = {
            "modality": self.modality,
            "sub_cmd": sub_cmd,
            "sub_cmd_params": params,
            "event": event,
            "on_keepalive": on_keepalive,
        }
        if auth:
            msg = struct.pack(">BB", self.modality, sub_cmd)
            if params is not None:
                msg += cbor.encode(params)
            kwargs["pin_uv_protocol"] = self.pin_uv_protocol.VERSION
            kwargs["pin_uv_param"] = self.pin_uv_protocol.authenticate(
                self.pin_uv_token, msg
            )
        return self.ctap.bio_enrollment(**kwargs)

    def get_fingerprint_sensor_info(self):
        """Get fingerprint sensor info.

        :return: A dict containing FINGERPRINT_KIND and MAX_SAMPLES_REQUIRES.
        """
        return self._call(FPBioEnrollment.CMD.GET_SENSOR_INFO, auth=False)

    def enroll_begin(self, timeout=None, event=None, on_keepalive=None):
        """Start fingerprint enrollment.

        Starts the process of enrolling a new fingerprint, and will wait for the user
        to scan their fingerprint once to provide an initial sample.

        :param timeout: Optional timeout in milliseconds.
        :return: A tuple containing the new template ID, the sample status, and the
            number of samples remaining to complete the enrollment.
        """
        result = self._call(
            FPBioEnrollment.CMD.ENROLL_BEGIN,
            {FPBioEnrollment.PARAM.TIMEOUT_MS: timeout},
            event=event,
            on_keepalive=on_keepalive,
        )
        return (
            result[BioEnrollment.RESULT.TEMPLATE_ID],
            FPBioEnrollment.FEEDBACK(result[BioEnrollment.RESULT.LAST_SAMPLE_STATUS]),
            result[BioEnrollment.RESULT.REMAINING_SAMPLES],
        )

    def enroll_capture_next(
        self, template_id, timeout=None, event=None, on_keepalive=None
    ):
        """Continue fingerprint enrollment.

        Continues enrolling a new fingerprint and will wait for the user to scan their
        fingerpring once to provide a new sample.
        Once the number of samples remaining is 0, the enrollment is completed.

        :param template_id: The template ID returned by a call to `enroll_begin`.
        :param timeout: Optional timeout in milliseconds.
        :return: A tuple containing the sample status, and the number of samples
            remaining to complete the enrollment.
        """
        result = self._call(
            FPBioEnrollment.CMD.ENROLL_CAPTURE_NEXT,
            {
                FPBioEnrollment.PARAM.TEMPLATE_ID: template_id,
                FPBioEnrollment.PARAM.TIMEOUT_MS: timeout,
            },
            event=event,
            on_keepalive=on_keepalive,
        )
        return (
            FPBioEnrollment.FEEDBACK(result[BioEnrollment.RESULT.LAST_SAMPLE_STATUS]),
            result[BioEnrollment.RESULT.REMAINING_SAMPLES],
        )

    def enroll_cancel(self):
        """Cancel any ongoing fingerprint enrollment."""
        self._call(FPBioEnrollment.CMD.ENROLL_CANCEL, auth=False)

    def enroll(self, timeout=None):
        """Convenience wrapper for doing fingerprint enrollment.

        See FPEnrollmentContext for details.
        :return: An initialized FPEnrollmentContext.
        """
        return FPEnrollmentContext(self, timeout)

    def enumerate_enrollments(self):
        """Get a dict of enrolled fingerprint templates which maps template ID's to
        their friendly names.

        :return: A dict of enrolled template_id -> name pairs.
        """
        try:
            return {
                t[BioEnrollment.TEMPLATE_INFO.ID]: t[BioEnrollment.TEMPLATE_INFO.NAME]
                for t in self._call(FPBioEnrollment.CMD.ENUMERATE_ENROLLMENTS)[
                    BioEnrollment.RESULT.TEMPLATE_INFOS
                ]
            }
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_OPTION:
                return []
            raise

    def set_name(self, template_id, name):
        """Set/Change the friendly name of a previously enrolled fingerprint template.

        :param template_id: The ID of the template to change.
        :param name: A friendly name to give the template.
        """
        self._call(
            FPBioEnrollment.CMD.SET_NAME,
            {
                BioEnrollment.TEMPLATE_INFO.ID: template_id,
                BioEnrollment.TEMPLATE_INFO.NAME: name,
            },
        )

    def remove_enrollment(self, template_id):
        """Remove a previously enrolled fingerprint template.

        :param template_id: The Id of the template to remove.
        """
        self._call(
            FPBioEnrollment.CMD.REMOVE_ENROLLMENT,
            {BioEnrollment.TEMPLATE_INFO.ID: template_id},
        )
