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
from .cose import CoseKey
from .hid import CTAPHID, CAPABILITY
from .utils import Timeout, sha256, hmac_sha256, bytes2int, int2bytes
from .attestation import Attestation, FidoU2FAttestation

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


def _parse_cbor(data):
    resp, rest = cbor.loads(data)
    if rest:
        raise ValueError('Extraneous data')
    return resp


class Info(bytes):
    """Binary CBOR encoded response data returned by the CTAP2 GET_INFO command.

    :param _: The binary content of the Info data.
    :ivar versions: The versions supported by the authenticator.
    :ivar extensions: The extensions supported by the authenticator.
    :ivar aaguid: The AAGUID of the authenticator.
    :ivar options: The options supported by the authenticator.
    :ivar max_msg_size: The max message size supported by the authenticator.
    :ivar pin_protocols: The PIN protocol versions supported by the
        authenticator.
    :ivar data: The Info members, in the form of a dict.
    """

    @unique
    class KEY(IntEnum):
        VERSIONS = 1
        EXTENSIONS = 2
        AAGUID = 3
        OPTIONS = 4
        MAX_MSG_SIZE = 5
        PIN_PROTOCOLS = 6

    def __init__(self, _):
        super(Info, self).__init__()

        data = dict((Info.KEY(k), v) for (k, v) in _parse_cbor(self).items())
        self.versions = data[Info.KEY.VERSIONS]
        self.extensions = data.get(Info.KEY.EXTENSIONS, [])
        self.aaguid = data[Info.KEY.AAGUID]
        self.options = data.get(Info.KEY.OPTIONS, {})
        self.max_msg_size = data.get(Info.KEY.MAX_MSG_SIZE, 1024)
        self.pin_protocols = data.get(
            Info.KEY.PIN_PROTOCOLS, [])
        self.data = data

    def __repr__(self):
        r = 'Info(versions: %r' % self.versions
        if self.extensions:
            r += ', extensions: %r' % self.extensions
        r += ', aaguid: %s' % hexstr(self.aaguid)
        if self.options:
            r += ', options: %r' % self.options
        r += ', max_message_size: %d' % self.max_msg_size
        if self.pin_protocols:
            r += ', pin_protocols: %r' % self.pin_protocols
        return r + ')'

    def __str__(self):
        return self.__repr__()


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
            raise ValueError('Wrong length')

    def __repr__(self):
        return ('AttestedCredentialData(aaguid: %s, credential_id: %s, '
                'public_key: %s') % (hexstr(self.aaguid),
                                     hexstr(self.credential_id),
                                     self.public_key)

    def __str__(self):
        return self.__repr__()

    @staticmethod
    def parse(data):
        """Parse the components of an AttestedCredentialData from a binary
        string, and return them.

        :param data: A binary string containing an attested credential data.
        :return: AAGUID, credential ID, public key, and remaining data.
        """
        aaguid = data[:16]
        c_len = struct.unpack('>H', data[16:18])[0]
        cred_id = data[18:18+c_len]
        pub_key, rest = cbor.loads(data[18+c_len:])
        return aaguid, cred_id, CoseKey.parse(pub_key), rest

    @classmethod
    def create(cls, aaguid, credential_id, public_key):
        """Create an AttestedCredentialData by providing its components.

        :param aaguid: The AAGUID of the authenticator.
        :param credential_id: The binary ID of the credential.
        :param public_key: A COSE formatted public key.
        :return: The attested credential data.
        """
        return cls(aaguid + struct.pack('>H', len(credential_id))
                   + credential_id + cbor.dumps(public_key))

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
        UP = 0x01
        UV = 0x04
        AT = 0x40
        ED = 0x80

    def __init__(self, _):
        super(AuthenticatorData, self).__init__()

        self.rp_id_hash = self[:32]
        self.flags = six.indexbytes(self, 32)
        self.counter = struct.unpack('>I', self[33:33+4])[0]
        rest = self[37:]

        if self.flags & AuthenticatorData.FLAG.AT:
            self.credential_data, rest = \
                AttestedCredentialData.unpack_from(self[37:])
        else:
            self.credential_data = None

        if self.flags & AuthenticatorData.FLAG.ED:
            self.extensions, rest = cbor.loads(rest)
        else:
            self.extensions = None

        if rest:
            raise ValueError('Wrong length')

    @classmethod
    def create(cls, rp_id_hash, flags, counter, credential_data=b'',
               extensions=None):
        """Create an AuthenticatorData instance.

        :param rp_id_hash: SHA256 hash of the RP ID.
        :param flags: Flags of the AuthenticatorData.
        :param counter: Signature counter of the authenticator data.
        :param credential_data: Authenticated credential data (only if AT flag
            is set).
        :param extensions: Authenticator extensions (only if ED flag is set).
        :return: The authenticator data.
        """
        return cls(
            rp_id_hash + struct.pack('>BI', flags, counter) + credential_data +
            (cbor.dumps(extensions) if extensions is not None else b'')
        )

    def __repr__(self):
        r = 'AuthenticatorData(rp_id_hash: %s, flags: 0x%02x, counter: %d' %\
            (hexstr(self.rp_id_hash), self.flags, self.counter)
        if self.credential_data:
            r += ', credential_data: %s' % self.credential_data
        if self.extensions:
            r += ', extensions: %s' % self.extensions
        return r + ')'

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
            name = re.sub('([a-z])([A-Z])', r'\1_\2', key).upper()
            return getattr(cls, name)

        @property
        def string_key(self):
            """Get the string used for this key in the Webauthn specification.

            :return: The Webauthn string used for a key.
            :rtype: str
            """
            value = ''.join(w.capitalize() for w in self.name.split('_'))
            return value[0].lower() + value[1:]

    def __init__(self, _):
        super(AttestationObject, self).__init__()

        data = dict((AttestationObject.KEY.for_key(k), v) for (k, v) in
                    _parse_cbor(self).items())
        self.fmt = data[AttestationObject.KEY.FMT]
        self.auth_data = AuthenticatorData(data[AttestationObject.KEY.AUTH_DATA]
                                           )
        data[AttestationObject.KEY.AUTH_DATA] = self.auth_data
        self.att_statement = data[
            AttestationObject.KEY.ATT_STMT]
        self.data = data

    def __repr__(self):
        return 'AttestationObject(fmt: %r, auth_data: %r, att_statement: %r)' %\
            (self.fmt, self.auth_data, self.att_statement)

    def __str__(self):
        return self.__repr__()

    def verify(self, client_param):
        """Verify the digital signature of an AttestationObject, with regard to
        the given client_param.

        :param client_param: SHA256 hash of the ClientData for the request.
        :type client_param: bytes
        """
        attestation = Attestation.for_type(self.fmt)
        if attestation:
            attestation().verify(self.att_statement, self.auth_data,
                                 client_param)
        else:
            raise ValueError('Unsupported format: %s' % self.fmt)

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
        return cls(cbor.dumps(args(fmt, auth_data, att_stmt)))

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
                AttestedCredentialData.create(
                    b'\0'*16,  # aaguid
                    registration.key_handle,
                    {  # EC256 public key
                        1: 2,
                        3: -7,
                        -1: 1,
                        -2: registration.public_key[1:1+32],
                        -3: registration.public_key[33:33+32]
                    }
                )
            ),
            {  # att_statement
                'x5c': [registration.certificate],
                'sig': registration.signature
            }
        )

    def with_int_keys(self):
        """Get a copy of this AttestationObject, using CTAP2 integer values as
        map keys in the CBOR representation.

        :return: The attestation object, using int keys.
        :rtype: AttestationObject
        """
        return AttestationObject(cbor.dumps(self.data))

    def with_string_keys(self):
        """Get a copy of this AttestationObject, using Webauthn string values as
        map keys in the CBOR representation.

        :return: The attestation object, using str keys.
        :rtype: AttestationObject
        """
        return AttestationObject(cbor.dumps(
            dict((k.string_key, v) for k, v in self.data.items())))


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

        data = dict((AssertionResponse.KEY(k), v) for (k, v) in
                    _parse_cbor(self).items())
        self.credential = data.get(
            AssertionResponse.KEY.CREDENTIAL)
        self.auth_data = AuthenticatorData(
            data[AssertionResponse.KEY.AUTH_DATA])
        self.signature = data[AssertionResponse.KEY.SIGNATURE]
        self.user = data.get(
            AssertionResponse.KEY.USER)
        self.number_of_credentials = data.get(
            AssertionResponse.KEY.N_CREDS)
        self.data = data

    def __repr__(self):
        r = 'AssertionResponse(credential: %r, auth_data: %r, signature: %s' %\
            (self.credential, self.auth_data, hexstr(self.signature))
        if self.user:
            r += ', user: %s' % self.user
        if self.number_of_credentials is not None:
            r += ', number_of_credentials: %d' % self.number_of_credentials
        return r + ')'

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
        return cls(cbor.dumps(args(credential, auth_data, signature, user,
                                   n_creds)))

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
                app_param,
                authentication.user_presence & 0x01,
                authentication.counter
            ),
            authentication.signature
        )


class CTAP2(object):
    """Implementation of the CTAP2 specification.

    :param device: A CtapHidDevice handle supporting CTAP2.
    """

    @unique
    class CMD(IntEnum):
        MAKE_CREDENTIAL = 0x01
        GET_ASSERTION = 0x02
        GET_INFO = 0x04
        CLIENT_PIN = 0x06
        RESET = 0x07
        GET_NEXT_ASSERTION = 0x08

    def __init__(self, device):
        if not device.capabilities & CAPABILITY.CBOR:
            raise ValueError('Device does not support CTAP2.')
        self.device = device

    def send_cbor(self, cmd, data=None, timeout=None, parse=_parse_cbor,
                  on_keepalive=None):

        """Sends a CBOR message to the device, and waits for a response.

        The optional parameter 'timeout' can either be a numeric time in seconds
        or a threading.Event object used to cancel the request.

        :param cmd: The command byte of the request.
        :param data: The payload to send (to be CBOR encoded).
        :param timeout: Optional timeout in seconds, or an instance of
            threading.Event used to cancel the command.
        :param parse: Function used to parse the binary response data, defaults
            to parsing the CBOR.
        :param on_keepalive: Optional function called when keep-alive is sent by
            the authenticator.
        :return: The result of calling the parse function on the response data
            (defaults to the CBOR decoded value).
        """
        request = struct.pack('>B', cmd)
        if data is not None:
            request += cbor.dumps(data)
        with Timeout(timeout) as event:
            response = self.device.call(CTAPHID.CBOR, request, event,
                                        on_keepalive)
        status = six.indexbytes(response, 0)
        if status != 0x00:
            raise CtapError(status)
        if len(response) == 1:
            return None
        return parse(response[1:])

    def make_credential(self, client_data_hash, rp, user, key_params,
                        exclude_list=None, extensions=None, options=None,
                        pin_auth=None, pin_protocol=None, timeout=None,
                        on_keepalive=None):
        """CTAP2 makeCredential operation,

        :param client_data_hash: SHA256 hash of the ClientData.
        :param rp: PublicKeyCredentialRpEntity parameters.
        :param user: PublicKeyCredentialUserEntity parameters.
        :param key_params: List of acceptable credential types.
        :param exclude_list: Optional list of PublicKeyCredentialDescriptors.
        :param extensions: Optional dict of extensions.
        :param options: Optional dict of options.
        :param pin_auth: Optional PIN auth parameter.
        :param pin_protocol: The version of PIN protocol used, if any.
        :param timeout: Optional timeout in seconds, or threading.Event object
            used to cancel the request.
        :param on_keepalive: Optional callback function to handle keep-alive
            messages from the authenticator.
        :return: The new credential.
        """
        return self.send_cbor(CTAP2.CMD.MAKE_CREDENTIAL, args(
            client_data_hash,
            rp,
            user,
            key_params,
            exclude_list,
            extensions,
            options,
            pin_auth,
            pin_protocol
        ), timeout, AttestationObject, on_keepalive)

    def get_assertion(self, rp_id, client_data_hash, allow_list=None,
                      extensions=None, options=None, pin_auth=None,
                      pin_protocol=None, timeout=None, on_keepalive=None):
        """CTAP2 getAssertion command.

        :param rp_id: SHA256 hash of the RP ID of the credential.
        :param client_data_hash: SHA256 hash of the ClientData used.
        :param allow_list: Optional list of PublicKeyCredentialDescriptors.
        :param extensions: Optional dict of extensions.
        :param options: Optional dict of options.
        :param pin_auth: Optional PIN auth parameter.
        :param pin_protocol: The version of PIN protocol used, if any.
        :param timeout: Optional timeout in seconds, or threading.Event object
            used to cancel the request.
        :param on_keepalive: Optional callback function to handle keep-alive
            messages from the authenticator.
        :return: The new assertion.
        """
        return self.send_cbor(CTAP2.CMD.GET_ASSERTION, args(
            rp_id,
            client_data_hash,
            allow_list,
            extensions,
            options,
            pin_auth,
            pin_protocol
        ), timeout, AssertionResponse, on_keepalive)

    def get_info(self):
        """CTAP2 getInfo command.

        :return: Information about the authenticator.
        """
        return self.send_cbor(CTAP2.CMD.GET_INFO, parse=Info)

    def client_pin(self, pin_protocol, sub_cmd, key_agreement=None,
                   pin_auth=None, new_pin_enc=None, pin_hash_enc=None):
        """CTAP2 clientPin command, used for various PIN operations.

        :param pin_protocol: The PIN protocol version to use.
        :param sub_cmd: A clientPin sub command.
        :param key_agreement: The keyAgreement parameter.
        :param pin_auth: The pinAuth parameter.
        :param new_pin_enc: The newPinEnc parameter.
        :param pin_hash_enc: The pinHashEnc parameter.
        :return: The response of the command, decoded.
        """
        return self.send_cbor(CTAP2.CMD.CLIENT_PIN, args(
            pin_protocol,
            sub_cmd,
            key_agreement,
            pin_auth,
            new_pin_enc,
            pin_hash_enc
        ))

    def reset(self, timeout=None, on_keepalive=None):
        """CTAP2 reset command, erases all credentials and PIN.

        :param timeout: Optional timeout in seconds, or threading.Event object
            used to cancel the request.
        :param on_keepalive: Optional callback function to handle keep-alive
            messages from the authenticator.
        """
        self.send_cbor(CTAP2.CMD.RESET, timeout=timeout,
                       on_keepalive=on_keepalive)

    def get_next_assertion(self):
        """CTAP2 getNextAssertion command.

        :return: The next available assertion response.
        """
        return self.send_cbor(CTAP2.CMD.GET_NEXT_ASSERTION,
                              parse=AssertionResponse)


def _pad_pin(pin):
    if not isinstance(pin, six.string_types):
        raise ValueError('PIN of wrong type, expecting %s' % six.string_types)
    if len(pin) < 4:
        raise ValueError('PIN must be >= 4 characters')
    pin = pin.encode('utf8').ljust(64, b'\0')
    pin += b'\0' * (-(len(pin) - 16) % 16)
    if len(pin) > 255:
        raise ValueError('PIN must be <= 255 bytes')
    return pin


class PinProtocolV1(object):
    """Implementation of the CTAP1 PIN protocol v1.

    :param ctap: An instance of a CTAP2 object.
    :cvar VERSION: The version number of the PIV protocol.
    :cvar IV: An all-zero IV used for some cryptographic operations.
    """
    VERSION = 1
    IV = b'\x00' * 16

    @unique
    class CMD(IntEnum):
        GET_RETRIES = 0x01
        GET_KEY_AGREEMENT = 0x02
        SET_PIN = 0x03
        CHANGE_PIN = 0x04
        GET_PIN_TOKEN = 0x05

    @unique
    class RESULT(IntEnum):
        KEY_AGREEMENT = 0x01
        PIN_TOKEN = 0x02
        RETRIES = 0x03

    def __init__(self, ctap):
        self.ctap = ctap

    def _init_shared_secret(self):
        be = default_backend()
        sk = ec.generate_private_key(ec.SECP256R1(), be)
        pn = sk.public_key().public_numbers()
        key_agreement = {
            1: 2,
            -1: 1,
            -2: int2bytes(pn.x, 32),
            -3: int2bytes(pn.y, 32)
        }

        resp = self.ctap.client_pin(PinProtocolV1.VERSION,
                                    PinProtocolV1.CMD.GET_KEY_AGREEMENT)
        pk = resp[PinProtocolV1.RESULT.KEY_AGREEMENT]
        x = bytes2int(pk[-2])
        y = bytes2int(pk[-3])
        pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(be)
        shared_secret = sha256(sk.exchange(ec.ECDH(), pk))  # x-coordinate, 32b
        return key_agreement, shared_secret

    def get_pin_token(self, pin):
        """Get a PIN token from the authenticator.

        :param pin: The PIN of the authenticator.
        :return: A PIN token.
        """
        key_agreement, shared_secret = self._init_shared_secret()

        be = default_backend()
        cipher = Cipher(algorithms.AES(shared_secret),
                        modes.CBC(PinProtocolV1.IV), be)
        pin_hash = sha256(pin.encode())[:16]
        enc = cipher.encryptor()
        pin_hash_enc = enc.update(pin_hash) + enc.finalize()

        resp = self.ctap.client_pin(PinProtocolV1.VERSION,
                                    PinProtocolV1.CMD.GET_PIN_TOKEN,
                                    key_agreement=key_agreement,
                                    pin_hash_enc=pin_hash_enc)
        dec = cipher.decryptor()
        return dec.update(resp[PinProtocolV1.RESULT.PIN_TOKEN]) + dec.finalize()

    def get_pin_retries(self):
        """Get the number of PIN retries remaining.

        :return: The number or PIN attempts until the authenticator is locked.
        """
        resp = self.ctap.client_pin(PinProtocolV1.VERSION,
                                    PinProtocolV1.CMD.GET_RETRIES)
        return resp[PinProtocolV1.RESULT.RETRIES]

    def set_pin(self, pin):
        """Set the PIN of the autenticator.
        This only works when no PIN is set. To change the PIN when set, use
        change_pin.

        :param pin: A PIN to set.
        """
        pin = _pad_pin(pin)
        key_agreement, shared_secret = self._init_shared_secret()

        be = default_backend()
        cipher = Cipher(algorithms.AES(shared_secret),
                        modes.CBC(PinProtocolV1.IV), be)
        enc = cipher.encryptor()
        pin_enc = enc.update(pin) + enc.finalize()
        pin_auth = hmac_sha256(shared_secret, pin_enc)[:16]
        self.ctap.client_pin(PinProtocolV1.VERSION, PinProtocolV1.CMD.SET_PIN,
                             key_agreement=key_agreement,
                             new_pin_enc=pin_enc,
                             pin_auth=pin_auth)

    def change_pin(self, old_pin, new_pin):
        """Change the PIN of the authenticator.
        This only works when a PIN is already set. If no PIN is set, use
        set_pin.

        :param old_pin: The currently set PIN.
        :param new_pin: The new PIN to set.
        """
        new_pin = _pad_pin(new_pin)
        key_agreement, shared_secret = self._init_shared_secret()

        be = default_backend()
        cipher = Cipher(algorithms.AES(shared_secret),
                        modes.CBC(PinProtocolV1.IV), be)
        pin_hash = sha256(old_pin.encode())[:16]
        enc = cipher.encryptor()
        pin_hash_enc = enc.update(pin_hash) + enc.finalize()
        enc = cipher.encryptor()
        new_pin_enc = enc.update(new_pin) + enc.finalize()
        pin_auth = hmac_sha256(shared_secret, new_pin_enc + pin_hash_enc)[:16]
        self.ctap.client_pin(PinProtocolV1.VERSION,
                             PinProtocolV1.CMD.CHANGE_PIN,
                             key_agreement=key_agreement,
                             pin_hash_enc=pin_hash_enc,
                             new_pin_enc=new_pin_enc,
                             pin_auth=pin_auth)
