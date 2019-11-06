# Copyright (c) 2019 Onica Group LLC.
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:

#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.

#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Structs based on Microsoft's WebAuthN API.
https://github.com/microsoft/webauthn
"""

# With the ctypes.Structure a lot of the property names
# will be invalid, and when creating the __init__ methods
# we do not need to call super() for the Structure class
#
# pylint: disable=invalid-name, super-init-not-called, too-few-public-methods

import ctypes
import sys
import six

from win32gui import GetForegroundWindow
from enum import Enum, unique
from typing import Dict, Union, List

from .ctap2 import AttestationObject, AuthenticatorData

WEBAUTHN = ctypes.windll.webauthn


class GUID(ctypes.Structure):
    """GUID Type in C++."""

    _fields_ = [("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8)]

    def __str__(self):
        # type: () -> str
        """Return string."""
        return '{%08X-%04X-%04X-%04X-%012X}' % (
            self.Data1, self.Data2, self.Data3,
            self.Data4[0] * 256 + self.Data4[1],
            self.Data4[2] * (256 ** 5)
            + self.Data4[3] * (256 ** 4)
            + self.Data4[4] * (256 ** 3)
            + self.Data4[5] * (256 ** 2)
            + self.Data4[6] * 256
            + self.Data4[7])


class WebAuthNCoseCredentialParameter(ctypes.Structure):
    """Maps to WEBAUTHN_COSE_CREDENTIAL_PARAMETER Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L185
    """

    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("pwszCredentialType", ctypes.wintypes.LPCWSTR),
        ("lAlg", ctypes.wintypes.LONG)
    ]

    def __init__(self, cred_type, alg):
        # type: (str, Union[str,int]) -> None
        """Init struct."""
        self.dwVersion = get_version(self.__class__.__name__)
        self.pwszCredentialType = ctypes.wintypes.LPCWSTR(cred_type)
        self.lAlg = ctypes.c_long(int(alg))


class WebAuthNCoseCredentialParameters(ctypes.Structure):
    """Maps to WEBAUTHN_COSE_CREDENTIAL_PARAMETERS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L191
    """

    _fields_ = [
        ("cCredentialParameters", ctypes.wintypes.DWORD),
        ("pCredentialParameters", ctypes.POINTER(WebAuthNCoseCredentialParameter))
    ]

    def __init__(self, public_key_params):
        # type: (List[Dict[str, str]]) -> None
        """Create pointer to array of structs."""
        num_of_creds = len(public_key_params)
        elems = (WebAuthNCoseCredentialParameter * num_of_creds)()

        for num in range(num_of_creds):
            elems[num] = WebAuthNCoseCredentialParameter(
                public_key_params[num]['type'],
                public_key_params[num]['alg']
            )

        self.pCredentialParameters = ctypes.cast(
            elems,
            ctypes.POINTER(WebAuthNCoseCredentialParameter)
        )
        self.cCredentialParameters = num_of_creds


class WebAuthNClientData(ctypes.Structure):
    """Maps to WEBAUTHN_CLIENT_DATA Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L153
    """

    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("cbClientDataJSON", ctypes.wintypes.DWORD),
        ("pbClientDataJSON", ctypes.wintypes.PBYTE),
        ("pwszHashAlgId", ctypes.wintypes.LPCWSTR)
    ]

    def __init__(self, client_data):
        """Init struct."""
        self.dwVersion = get_version(self.__class__.__name__)
        self.cbClientDataJSON = ctypes.wintypes.DWORD(len(client_data))
        self.pbClientDataJSON = ctypes.cast(client_data, ctypes.POINTER(ctypes.c_byte))
        self.pwszHashAlgId = ctypes.wintypes.LPCWSTR('SHA-256')


class WebAuthNRpEntityInformation(ctypes.Structure):
    """Maps to WEBAUTHN_RP_ENTITY_INFORMATION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L98
    """

    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("pwszId", ctypes.POINTER(ctypes.c_wchar)),
        ("pwszName", ctypes.POINTER(ctypes.c_wchar)),
        ("pwszIcon", ctypes.POINTER(ctypes.c_wchar))
    ]

    def __init__(self, rp_id, name, icon=None):
        # type: (str, str, str) -> None
        """Init struct."""
        self.dwVersion = get_version(self.__class__.__name__)
        self.pwszId = to_unicode_buffer(rp_id)
        self.pwszName = to_unicode_buffer(name)

        if icon:
            self.pwszIcon = to_unicode_buffer(icon)


class WebAuthNUserEntityInformation(ctypes.Structure):
    """Maps to WEBAUTHN_USER_ENTITY_INFORMATION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L127
    """

    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("cbId", ctypes.wintypes.DWORD),
        ("pbId", ctypes.wintypes.PBYTE),
        ("pwszName", ctypes.POINTER(ctypes.c_wchar)),
        ("pwszIcon", ctypes.POINTER(ctypes.c_wchar)),
        ("pwszDisplayName", ctypes.POINTER(ctypes.c_wchar))
    ]

    def __init__(self, user_id, user_name, icon=None, display_name=None):
        # type: (str, str, str, str) -> None
        """Init struct."""
        user = to_unicode_buffer(user_id)

        self.dwVersion = get_version(self.__class__.__name__)
        self.cbId = ctypes.wintypes.DWORD(len(user_id))
        self.pbId = ctypes.cast(user, ctypes.POINTER(ctypes.c_byte))
        self.pwszName = to_unicode_buffer(user_name)

        if icon:
            self.pwszIcon = to_unicode_buffer(icon)

        if display_name:
            self.pwszDisplayName = to_unicode_buffer(display_name)


class WebAuthNCredentialEx(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL_EX Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L250
    """

    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("cbId", ctypes.wintypes.DWORD),
        ("pbId", ctypes.wintypes.PBYTE),
        ("pwszCredentialType", ctypes.wintypes.LPCWSTR),
        ("dwTransports", ctypes.wintypes.DWORD)
    ]

    def __init__(self, cred_id, cred_type, transport):
        # type: (str, str, WebAuthNCTAPTransport) -> None
        """
        Initialize struct about credential with extra information, such as,
        dwTransports.

        Args:
            cred_id (str): Unique ID for this particular credential.
            cred_type (str): Well-known credential type specifying what
                this particular credential is.
            transport (WebAuthNCTAPTransport): Transports. 0 implies no transport
                restrictions.
        """
        self.dwVersion = get_version(self.__class__.__name__)
        self.cbId = ctypes.wintypes.DWORD(len(cred_id))
        self.pbId = ctypes.cast(to_unicode_buffer(cred_id), ctypes.POINTER(
            ctypes.c_byte))
        self.pwszCredentialType = ctypes.wintypes.LPCWSTR(cred_type)
        self.dwTransports = ctypes.wintypes.DWORD(transport.value)


class WebAuthNCredentialList(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL_LIST Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L261
    """

    _fields_ = [
        ("cCredentials", ctypes.wintypes.DWORD),
        ("ppCredentials", ctypes.POINTER(ctypes.POINTER(WebAuthNCredentialEx)))
    ]

    def __init__(self, credentials):
        # type: (List[Dict[str,str]]) -> None
        """Create pointer to array of structs."""
        num_of_creds = len(credentials)
        elems = (ctypes.POINTER(WebAuthNCredentialEx) * num_of_creds)()

        for num in range(num_of_creds):
            transport = WebAuthNCTAPTransport[credentials[num].get('transport', 'USB')]
            elems[num].contents = WebAuthNCredentialEx(
                credentials[num]['id'],
                credentials[num]['type'],
                transport
            )

        self.ppCredentials = ctypes.cast(
            elems,
            ctypes.POINTER(ctypes.POINTER(WebAuthNCredentialEx))
        )
        self.cCredentials = num_of_creds


class WebAuthNExtension(ctypes.Structure):
    """Maps to WEBAUTHN_EXTENSION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L317
    """

    _fields_ = [
        ("pwszExtensionIdentifier", ctypes.wintypes.LPCWSTR),
        ("cbExtension", ctypes.wintypes.DWORD),
        ("pvExtension", ctypes.POINTER(ctypes.c_ubyte))
    ]


class WebAuthNExtensions(ctypes.Structure):
    """Maps to WEBAUTHN_EXTENSIONS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L324
    """

    _fields_ = [
        ("cExtensions", ctypes.wintypes.DWORD),
        ("pExtensions", ctypes.POINTER(WebAuthNExtension))
    ]


class WebAuthNCredential(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L212
    """

    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("cbId", ctypes.wintypes.DWORD),
        ("pbId", ctypes.wintypes.PBYTE),
        ("pwszCredentialType", ctypes.wintypes.LPCWSTR)
    ]

    def __init__(self, cred_id, cred_type):
        # type: (str, str) -> None
        """Init information about credential."""
        self.cbId = ctypes.wintypes.DWORD(len(cred_id))
        self.pbId = ctypes.cast(to_unicode_buffer(cred_id), ctypes.POINTER(
            ctypes.c_byte))
        self.pwszCredentialType = ctypes.wintypes.LPCWSTR(cred_type)


class WebAuthNCredentials(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIALS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L219
    """

    _fields_ = [
        ("cCredentials", ctypes.wintypes.DWORD),
        ("pCredentials", ctypes.POINTER(WebAuthNCredential))
    ]

    def __init__(self, credentials):
        # type: (List[Dict[str,str]]) -> None
        """Create pointer to array of structs."""
        num_of_creds = len(credentials)
        elems = (WebAuthNCredential * num_of_creds)()

        for num in range(num_of_creds):
            elems[num] = WebAuthNCredential(
                credentials[num]['id'],
                credentials[num]['type']
            )

        self.pCredentials = ctypes.cast(
            elems,
            ctypes.POINTER(WebAuthNCredential)
        )
        self.cCredentials = num_of_creds


class WebAuthNGetAssertionOptions(ctypes.Structure):
    """Maps to WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L452
    """

    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("dwTimeoutMilliseconds", ctypes.wintypes.DWORD),
        ("CredentialList", WebAuthNCredentials),
        ("Extensions", WebAuthNExtensions),
        ("dwAuthenticatorAttachment", ctypes.wintypes.DWORD),
        ("dwUserVerificationRequirement", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("pwszU2fAppId", ctypes.POINTER(ctypes.c_wchar)),  # PCWSTR type
        ("pbU2fAppId", ctypes.wintypes.BOOL),
        ("pCancellationId", ctypes.POINTER(GUID)),
        ("pAllowCredentialList", ctypes.POINTER(WebAuthNCredentialList))
    ]

    def __init__(self,
                 timeout,
                 attachment,
                 user_verification_requirement,
                 credentials=None
                 ):
        # type: (...) -> None
        """Get Assertion options.

        Args:
            timeout (int): Time that the operation is expected to complete within.This
                is used as guidance, and can be overridden by the platform.
            attachment (WebAuthNAuthenticatorAttachment): Platform vs Cross-Platform
                Authenticators.
            user_verification_requirement (WebAuthNUserVerificationRequirement): User
                Verification Requirement.
            credentials (WebAuthNCredentials, WebAuthNCredentialList): Allowed
                Credentials List.
        """
        self.dwVersion = get_version(self.__class__.__name__)
        self.dwTimeoutMilliseconds = int(timeout)
        self.dwAuthenticatorAttachment = ctypes.wintypes.DWORD(attachment.value)
        self.dwUserVerificationRequirement = ctypes.wintypes.DWORD(
            user_verification_requirement.value)

        # When credentials are specified in as either a struct of
        # WebAuthNCredentialList or WebAuthNCredentials
        # the call to WebAuthNAuthenticatorGetAssertion fails. When the are omitted,
        # the call succeeds.
        # ----------------------------------------------------------------------------
        # if self.dwVersion >= 4:
        #     self.pAllowCredentialList = (ctypes.pointer(
        #         WebAuthNCredentialList(credentials)
        #     ))
        # else:
        #     self.CredentialList = WebAuthNCredentials(credentials)
        # ----------------------------------------------------------------------------


class WebAuthNAssertion(ctypes.Structure):
    """Maps to WEBAUTHN_ASSERTION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L616
    """

    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("cbAuthenticatorData", ctypes.wintypes.DWORD),
        ("pbAuthenticatorData", ctypes.wintypes.PBYTE),
        ("cbSignature", ctypes.wintypes.DWORD),
        ("pbSignature", ctypes.wintypes.PBYTE),
        ("Credential", WebAuthNCredential),
        ("cbUserId", ctypes.wintypes.DWORD),
        ("pbUserId", ctypes.wintypes.PBYTE)
    ]

    @property
    def auth_data(self):
        # type: () -> AuthenticatorData
        """Convert pbAuthenticatorData to AuthenticatorData."""
        return AuthenticatorData(
            to_byte_array(self.pbAuthenticatorData, self.cbAuthenticatorData)
        )

    @property
    def signature(self):
        # type: () -> List[ctypes.c_byte]
        """Convert pbSignature to string."""
        return to_byte_array(self.pbSignature, self.cbSignature)

    @property
    def credential(self):
        # type: () -> List[ctypes.c_byte]
        """Get credential_id from Credential."""
        return {
            'id': to_byte_array(self.Credential.pbId, self.Credential.cbId),
            'type': self.Credential.pwszCredentialType
        }


class WebAuthNMakeCredentialOptions(ctypes.Structure):
    """maps to WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L394
    """

    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("dwTimeoutMilliseconds", ctypes.wintypes.DWORD),
        ("CredentialList", WebAuthNCredentials),
        ("Extensions", WebAuthNExtensions),
        ("dwAuthenticatorAttachment", ctypes.wintypes.DWORD),
        ("bRequireResidentKey", ctypes.wintypes.BOOL),
        ("dwUserVerificationRequirement", ctypes.wintypes.DWORD),
        ("dwAttestationConveyancePreference", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("pCancellationId", ctypes.POINTER(GUID)),
        ("pExcludeCredentialList", ctypes.POINTER(WebAuthNCredentialList))
    ]

    def __init__(self,
                 timeout,
                 require_resident_key,
                 attachment,
                 user_verification_requirement,
                 attestation_convoyence,
                 credentials=(None)
                 ):
        """Make Credential Options.

        Args:
            timeout (int): Time that the operation is expected to complete within.This
                is used as guidance, and can be overridden by the platform.
            require_resident_key (bool): Require key to be resident or not.
                                         Defaulting to FALSE.
            attachment (WebAuthNAuthenticatorAttachment): Platform vs Cross-Platform
                                                          Authenticators.
            user_verification_requirement (WebAuthNUserVerificationRequirement): User
                Verification Requirement.
            attestation_convoyence (WebAuthNAttestationConvoyancePreference):
                Attestation Conveyance Preference.
            credentials (WebAuthNCredentials, WebAuthNCredentialList): Credentials used
                for exclusion.
        """
        self.dwVersion = get_version(self.__class__.__name__)
        self.dwTimeoutMilliseconds = int(timeout)
        self.bRequireResidentKey = ctypes.wintypes.BOOL(require_resident_key)
        self.dwAuthenticatorAttachment = ctypes.wintypes.DWORD(attachment.value)
        self.dwUserVerificationRequirement = ctypes.wintypes.DWORD(
            user_verification_requirement.value)
        self.dwAttestationConveyancePreference = ctypes.wintypes.DWORD(
            attestation_convoyence.value)

        # Whether or not these excluded credentials are specified in
        # WebAuthNMakeCredentialOptions
        # as a struct of WebAuthNCredentialList or WebAuthNCredentials
        # either way, the call to WebAuthNAuthenticatorMakeCredential stills succeeds
        # ----------------------------------------------------------------------------
        if self.dwVersion >= 3:
            self.pExcludeCredentialList = ctypes.pointer(
                WebAuthNCredentialList(credentials)
            )
        else:
            self.CredentialList = WebAuthNCredentials(credentials)
        # ----------------------------------------------------------------------------


class WebAuthNCredentialAttestation(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL_ATTESTATION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L582
    """

    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("pwszFormatType", ctypes.wintypes.LPCWSTR),
        ("cbAuthenticatorData", ctypes.wintypes.DWORD),
        ("pbAuthenticatorData", ctypes.wintypes.PBYTE),
        ("cbAttestation", ctypes.wintypes.DWORD),
        ("pbAttestation", ctypes.wintypes.PBYTE),
        ("dwAttestationDecodeType", ctypes.wintypes.DWORD),
        ("pvAttestationDecode", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbAttestationObject", ctypes.wintypes.DWORD),
        ("pbAttestationObject", ctypes.wintypes.PBYTE),
        ("cbCredentialId", ctypes.wintypes.DWORD),
        ("pbCredentialId", ctypes.wintypes.PBYTE),
        ("Extensions", WebAuthNExtensions),
        ("dwUsedTransport", ctypes.wintypes.DWORD)
    ]

    def to_attestation_object(self):
        # type: () -> AttestationObject
        """Convert received WebAuthNCredentialAttestation to AttestationObject."""
        return AttestationObject(
            to_byte_array(self.pbAttestationObject, self.cbAttestationObject)
        )


@unique
class WebAuthNUserVerificationRequirement(Enum):
    """Maps to WEBAUTHN_USER_VERIFICATION_REQUIREMENT_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L335
    """

    any = 0
    required = 1
    preferred = 2
    discouraged = 3


@unique
class WebAuthNAttestationConvoyancePreference(Enum):
    """Maps to WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L340
    """

    any = 0
    none = 1
    indirect = 2
    direct = 3


@unique
class WebAuthNAuthenticatorAttachment(Enum):
    """Maps to WEBAUTHN_AUTHENTICATOR_ATTACHMENT_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L330
    """

    any = 0
    platform = 1
    cross_platform = 2
    cross_platform_u2f_v2 = 3


@unique
class WebAuthNCTAPTransport(Enum):
    """Maps to WEBAUTHN_CTAP_TRANSPORT_USB_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L225
    """

    USB = 0x00000001
    NFC = 0x00000002
    BLE = 0x00000004
    TEST = 0x00000008
    INTERNAL = 0x00000010
    FLAGS_MASK = 0x0000001F


@unique
class WEBAUTHN_TYPE(six.text_type, Enum):
    MAKE_CREDENTIAL = "webauthn.create"
    GET_ASSERTION = "webauthn.get"


WEBAUTHN_API_VERSION = WEBAUTHN.WebAuthNGetApiVersionNumber()
# The following is derived from
# https://github.com/microsoft/webauthn/blob/master/webauthn.h#L37

WEBAUTHN_STRUCT_VERSIONS = {
    1: {"WebAuthNRpEntityInformation": 1,
        "WebAuthNUserEntityInformation": 1,
        "WebAuthNClientData": 1,
        "WebAuthNCoseCredentialParameter": 1,
        "WebAuthNCredential": 1,
        "WebAuthNCredentialEx": 1,
        "WebAuthNMakeCredentialOptions": 3,
        "WebAuthNGetAssertionOptions": 4,
        "WEBAUTHN_COMMON_ATTESTATION": 1,
        "WebAuthNCredentialAttestation": 3,
        "WebAuthNAssertion": 1},
    2: {}
}  # type: Dict[int, Dict[str, int]]


def get_version(class_name):
    # type: (str) -> int
    """Get version of struct."""
    if class_name in WEBAUTHN_STRUCT_VERSIONS[WEBAUTHN_API_VERSION]:
        return WEBAUTHN_STRUCT_VERSIONS[WEBAUTHN_API_VERSION][class_name]

    return WEBAUTHN_STRUCT_VERSIONS[1][class_name]


def to_unicode_buffer(value):
    # type: (str) -> Union[ctypes._CData, ctypes._CArgObject]
    """Convert value to a unicode buffer using ctypes."""
    return ctypes.create_unicode_buffer(str(value))


def to_byte_array(pbyte, dword):
    # type: (ctypes.wintypes.PBYTE, ctypes.wintypes.DWORD) -> List[ctypes.c_byte]
    """Convert pbytes to something usable in python."""
    return ctypes.cast(pbyte, ctypes.POINTER(ctypes.c_byte * dword)).contents


class Info(object):
    """Empty class derived from CTAP Info class."""

    def __init__(self):
        super(Info, self).__init__()

        self.versions = None
        self.extensions = []
        self.aaguid = None
        self.options = {}
        self.max_msg_size = 1024
        self.pin_protocols = []
        self.max_creds_in_list = -1
        self.max_cred_id_length = -1
        self.transports = []
        self.algorithms = None
        self.data = None


class WinAPI(object):
    """Implementation of Microsoft's WebAuthN APIs."""

    def get_info(self):
        """Empty info."""
        return Info()

    def make_credential(
        self,
        client_data,
        rp,
        user,
        key_params,
        exclude_list=None,
        extensions=None,
        options=None,
        timeout=None
    ):
        """Make credential using Windows WebAuthN API"""
        rp_info = WebAuthNRpEntityInformation(rp['id'], rp['name'])
        user_info = WebAuthNUserEntityInformation(user['id'], user['name'])
        cose_cred_params = WebAuthNCoseCredentialParameters(key_params)
        webauthn_client_data = WebAuthNClientData(client_data)

        # TODO: add support for extensions
        make_cred_options = WebAuthNMakeCredentialOptions(
            timeout,
            options.get('rk', True),
            WebAuthNAuthenticatorAttachment.cross_platform,
            WebAuthNUserVerificationRequirement.any,
            WebAuthNAttestationConvoyancePreference.direct,
            exclude_list
        )

        WEBAUTHN.WebAuthNAuthenticatorMakeCredential.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.POINTER(WebAuthNRpEntityInformation),
            ctypes.POINTER(WebAuthNUserEntityInformation),
            ctypes.POINTER(WebAuthNCoseCredentialParameters),
            ctypes.POINTER(WebAuthNClientData),
            ctypes.POINTER(WebAuthNMakeCredentialOptions),
            ctypes.POINTER(ctypes.POINTER(WebAuthNCredentialAttestation))
        ]
        WEBAUTHN.WebAuthNAuthenticatorMakeCredential.restype = ctypes.c_int

        handle = GetForegroundWindow()

        attestation_pointer = ctypes.POINTER(WebAuthNCredentialAttestation)()
        result = WEBAUTHN.WebAuthNAuthenticatorMakeCredential(
            handle,
            ctypes.byref(rp_info),
            ctypes.byref(user_info),
            ctypes.byref(cose_cred_params),
            ctypes.byref(webauthn_client_data),
            ctypes.byref(make_cred_options),
            ctypes.byref(attestation_pointer))

        if result != 0:
            WEBAUTHN.WebAuthNGetErrorName.argtypes = [ctypes.HRESULT]
            WEBAUTHN.WebAuthNGetErrorName.restype = ctypes.c_wchar_p
            error = WEBAUTHN.WebAuthNGetErrorName(result)

            print('Failed to make credential using WebAuthN API: %s' % error)
            return sys.exit(1)

        return attestation_pointer.contents.to_attestation_object()

    def get_assertion(
        self,
        client_data,
        rp_id,
        allow_list,
        extensions,
        options,
        timeout
    ):
        """Get assertion using Windows WebAuthN API."""

        if options:
            uv = options.get('uv', False)
        else:
            uv = False

        webauthn_client_data = WebAuthNClientData(client_data)
        assertion_options = WebAuthNGetAssertionOptions(
            timeout,
            WebAuthNAuthenticatorAttachment.cross_platform,  # TODO: is this correct?
            WebAuthNUserVerificationRequirement.required if uv else
            WebAuthNUserVerificationRequirement.any,
            allow_list
        )

        WEBAUTHN.WebAuthNAuthenticatorGetAssertion.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.LPCWSTR,
            ctypes.POINTER(WebAuthNClientData),
            ctypes.POINTER(WebAuthNGetAssertionOptions),
            ctypes.POINTER(ctypes.POINTER(WebAuthNAssertion))
        ]
        WEBAUTHN.WebAuthNAuthenticatorGetAssertion.restype = ctypes.c_int

        handle = GetForegroundWindow()
        assertion_pointer = ctypes.POINTER(WebAuthNAssertion)()
        result = WEBAUTHN.WebAuthNAuthenticatorGetAssertion(
            handle,
            rp_id,
            ctypes.pointer(webauthn_client_data),
            ctypes.pointer(assertion_options),
            ctypes.pointer(assertion_pointer))

        if result != 0:
            WEBAUTHN.WebAuthNGetErrorName.argtypes = [ctypes.HRESULT]
            WEBAUTHN.WebAuthNGetErrorName.restype = ctypes.c_wchar_p
            error = WEBAUTHN.WebAuthNGetErrorName(result)

            print('Failed to make credential using WebAuthN API: %s' % error)
            return sys.exit(1)

        return [assertion_pointer.contents]
