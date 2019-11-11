# Copyright (c) 2019 Onica Group LLC.
# Modified work Copyright 2019 Yubico.
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
from ctypes.wintypes import BOOL, DWORD, LONG, LPCWSTR, HWND
import sys

from enum import IntEnum, unique

from .ctap2 import AttestationObject

PBYTE = ctypes.POINTER(ctypes.c_ubyte)  # Different from wintypes.PBYTE, which is signed
PCWSTR = ctypes.c_wchar_p


class BytesProperty(object):
    """Property for structs storing byte arrays as DWORD + PBYTE.

    Allows for easy reading/writing to struct fields using Python bytes objects.
    """

    def __init__(self, name):
        self.cbName = "cb" + name
        self.pbName = "pb" + name

    def __get__(self, instance, owner):
        return bytes(
            bytearray(getattr(instance, self.pbName)[: getattr(instance, self.cbName)])
        )

    def __set__(self, instance, value):
        setattr(instance, self.cbName, len(value))
        setattr(instance, self.pbName, ctypes.cast(value, PBYTE))


class GUID(ctypes.Structure):
    """GUID Type in C++."""

    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    def __str__(self):
        # type: () -> str
        """Return string."""
        return "{%08X-%04X-%04X-%04X-%012X}" % (
            self.Data1,
            self.Data2,
            self.Data3,
            self.Data4[0] * 256 + self.Data4[1],
            self.Data4[2] * (256 ** 5)
            + self.Data4[3] * (256 ** 4)
            + self.Data4[4] * (256 ** 3)
            + self.Data4[5] * (256 ** 2)
            + self.Data4[6] * 256
            + self.Data4[7],
        )


class WebAuthNCoseCredentialParameter(ctypes.Structure):
    """Maps to WEBAUTHN_COSE_CREDENTIAL_PARAMETER Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L185
    """

    _fields_ = [("dwVersion", DWORD), ("pwszCredentialType", LPCWSTR), ("lAlg", LONG)]

    def __init__(self, cred_type, alg):
        # type: (str, Union[str,int]) -> None
        """Init struct."""
        self.dwVersion = get_version(self.__class__.__name__)
        self.pwszCredentialType = cred_type
        self.lAlg = alg


class WebAuthNCoseCredentialParameters(ctypes.Structure):
    """Maps to WEBAUTHN_COSE_CREDENTIAL_PARAMETERS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L191
    """

    _fields_ = [
        ("cCredentialParameters", DWORD),
        ("pCredentialParameters", ctypes.POINTER(WebAuthNCoseCredentialParameter)),
    ]

    def __init__(self, params):
        # type: (List[Dict[str, str]]) -> None
        """Create pointer to array of structs."""
        self.cCredentialParameters = len(params)
        self.pCredentialParameters = (WebAuthNCoseCredentialParameter * len(params))(
            *(
                WebAuthNCoseCredentialParameter(param["type"], param["alg"])
                for param in params
            )
        )


class WebAuthNClientData(ctypes.Structure):
    """Maps to WEBAUTHN_CLIENT_DATA Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L153
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbClientDataJSON", DWORD),
        ("pbClientDataJSON", PBYTE),
        ("pwszHashAlgId", LPCWSTR),
    ]

    json = BytesProperty("ClientDataJSON")

    def __init__(self, client_data):
        """Init struct."""
        self.dwVersion = get_version(self.__class__.__name__)
        self.json = client_data
        self.pwszHashAlgId = "SHA-256"


class WebAuthNRpEntityInformation(ctypes.Structure):
    """Maps to WEBAUTHN_RP_ENTITY_INFORMATION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L98
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("pwszId", PCWSTR),
        ("pwszName", PCWSTR),
        ("pwszIcon", PCWSTR),
    ]

    def __init__(self, rp):
        # type: (Dict[str,Union[str,bytes]]) -> None
        """Init struct."""
        self.dwVersion = get_version(self.__class__.__name__)
        self.pwszId = rp["id"]
        self.pwszName = rp["name"]
        self.pwszIcon = rp.get("icon")


class WebAuthNUserEntityInformation(ctypes.Structure):
    """Maps to WEBAUTHN_USER_ENTITY_INFORMATION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L127
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbId", DWORD),
        ("pbId", PBYTE),
        ("pwszName", PCWSTR),
        ("pwszIcon", PCWSTR),
        ("pwszDisplayName", PCWSTR),
    ]

    id = BytesProperty("Id")

    def __init__(self, user):
        # type: (Dict[str, Union[str,bytes]]) -> None
        """Init struct."""

        self.dwVersion = get_version(self.__class__.__name__)
        self.id = user["id"]
        self.pwszName = user["name"]
        self.pwszIcon = user.get("icon")
        self.pwszDisplayName = user.get("displayName")


class WebAuthNCredentialEx(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL_EX Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L250
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbId", DWORD),
        ("pbId", PBYTE),
        ("pwszCredentialType", LPCWSTR),
        ("dwTransports", DWORD),
    ]

    id = BytesProperty("Id")

    def __init__(self, cred):
        # type: (Dict[str, str]) -> None
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
        self.id = cred["id"]
        self.pwszCredentialType = cred["type"]
        self.dwTransports = WebAuthNCTAPTransport[cred.get("transport", "USB")]


class WebAuthNCredentialList(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL_LIST Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L261
    """

    _fields_ = [
        ("cCredentials", DWORD),
        ("ppCredentials", ctypes.POINTER(ctypes.POINTER(WebAuthNCredentialEx))),
    ]

    def __init__(self, credentials):
        # type: (List[Dict[str,str]]) -> None
        """Create pointer to array of structs."""
        self.cCredentials = len(credentials)
        self.ppCredentials = (ctypes.POINTER(WebAuthNCredentialEx) * len(credentials))(
            *(ctypes.pointer(WebAuthNCredentialEx(cred)) for cred in credentials)
        )


class WebAuthNExtension(ctypes.Structure):
    """Maps to WEBAUTHN_EXTENSION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L317
    """

    _fields_ = [
        ("pwszExtensionIdentifier", LPCWSTR),
        ("cbExtension", DWORD),
        ("pvExtension", PBYTE),
    ]


class WebAuthNExtensions(ctypes.Structure):
    """Maps to WEBAUTHN_EXTENSIONS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L324
    """

    _fields_ = [
        ("cExtensions", DWORD),
        ("pExtensions", ctypes.POINTER(WebAuthNExtension)),
    ]


class WebAuthNCredential(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L212
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbId", DWORD),
        ("pbId", PBYTE),
        ("pwszCredentialType", LPCWSTR),
    ]

    id = BytesProperty("Id")

    def __init__(self, cred):
        # type: (str, str) -> None
        """Init information about credential."""
        self.id = cred["id"]
        self.pwszCredentialType = cred["type"]

    @property
    def descriptor(self):
        return {"type": self.pwszCredentialType, "id": self.id}


class WebAuthNCredentials(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIALS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L219
    """

    _fields_ = [
        ("cCredentials", DWORD),
        ("pCredentials", ctypes.POINTER(WebAuthNCredential)),
    ]

    def __init__(self, credentials):
        # type: (List[Dict[str,str]]) -> None
        """Create pointer to array of structs."""
        self.cCredentials = len(credentials)
        self.pCredentials = (WebAuthNCredential * len(credentials))(
            *(WebAuthNCredential(cred) for cred in credentials)
        )


class WebAuthNGetAssertionOptions(ctypes.Structure):
    """Maps to WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L452
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("dwTimeoutMilliseconds", DWORD),
        ("CredentialList", WebAuthNCredentials),
        ("Extensions", WebAuthNExtensions),
        ("dwAuthenticatorAttachment", DWORD),
        ("dwUserVerificationRequirement", DWORD),
        ("dwFlags", DWORD),
        ("pwszU2fAppId", PCWSTR),
        ("pbU2fAppId", BOOL),
        ("pCancellationId", ctypes.POINTER(GUID)),
        ("pAllowCredentialList", ctypes.POINTER(WebAuthNCredentialList)),
    ]

    def __init__(self, timeout, attachment, user_verification_requirement, credentials):
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
        self.dwTimeoutMilliseconds = timeout
        self.dwAuthenticatorAttachment = attachment
        self.dwUserVerificationRequirement = user_verification_requirement

        if self.dwVersion >= 4:
            clist = WebAuthNCredentialList(credentials)
            self.pAllowCredentialList = ctypes.pointer(clist)
        else:
            self.CredentialList = WebAuthNCredentials(credentials)


class WebAuthNAssertion(ctypes.Structure):
    """Maps to WEBAUTHN_ASSERTION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L616
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbAuthenticatorData", DWORD),
        ("pbAuthenticatorData", PBYTE),
        ("cbSignature", DWORD),
        ("pbSignature", PBYTE),
        ("Credential", WebAuthNCredential),
        ("cbUserId", DWORD),
        ("pbUserId", PBYTE),
    ]

    auth_data = BytesProperty("AuthenticatorData")
    signature = BytesProperty("Signature")
    user_id = BytesProperty("UserId")

    def __del__(self):
        WEBAUTHN.WebAuthNFreeAssertion(ctypes.byref(self))

    @property
    def credential(self):
        # type: () -> List[ctypes.c_byte]
        """Get credential_id from Credential."""
        return self.Credential.descriptor


class WebAuthNMakeCredentialOptions(ctypes.Structure):
    """maps to WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L394
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("dwTimeoutMilliseconds", DWORD),
        ("CredentialList", WebAuthNCredentials),
        ("Extensions", WebAuthNExtensions),
        ("dwAuthenticatorAttachment", DWORD),
        ("bRequireResidentKey", BOOL),
        ("dwUserVerificationRequirement", DWORD),
        ("dwAttestationConveyancePreference", DWORD),
        ("dwFlags", DWORD),
        ("pCancellationId", ctypes.POINTER(GUID)),
        ("pExcludeCredentialList", ctypes.POINTER(WebAuthNCredentialList)),
    ]

    def __init__(
        self,
        timeout,
        require_resident_key,
        attachment,
        user_verification_requirement,
        attestation_convoyence,
        credentials,
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
        self.dwTimeoutMilliseconds = timeout
        self.bRequireResidentKey = require_resident_key
        self.dwAuthenticatorAttachment = attachment
        self.dwUserVerificationRequirement = user_verification_requirement
        self.dwAttestationConveyancePreference = attestation_convoyence

        if self.dwVersion >= 3:
            self.pExcludeCredentialList = ctypes.pointer(
                WebAuthNCredentialList(credentials)
            )
        else:
            self.CredentialList = WebAuthNCredentials(credentials)


class WebAuthNCredentialAttestation(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL_ATTESTATION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L582
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("pwszFormatType", LPCWSTR),
        ("cbAuthenticatorData", DWORD),
        ("pbAuthenticatorData", PBYTE),
        ("cbAttestation", DWORD),
        ("pbAttestation", PBYTE),
        ("dwAttestationDecodeType", DWORD),
        ("pvAttestationDecode", PBYTE),
        ("cbAttestationObject", DWORD),
        ("pbAttestationObject", PBYTE),
        ("cbCredentialId", DWORD),
        ("pbCredentialId", PBYTE),
        ("Extensions", WebAuthNExtensions),
        ("dwUsedTransport", DWORD),
    ]

    auth_data = BytesProperty("AuthenticatorData")
    attestation = BytesProperty("Attestation")
    attestation_object = BytesProperty("AttestationObject")
    credential_id = BytesProperty("CredentialId")

    def __del__(self):
        WEBAUTHN.WebAuthNFreeCredentialAttestation(ctypes.byref(self))

    def to_attestation_object(self):
        # type: () -> AttestationObject
        """Convert received WebAuthNCredentialAttestation to AttestationObject."""
        return AttestationObject(
            to_byte_array(self.pbAttestationObject, self.cbAttestationObject)
        )


@unique
class WebAuthNUserVerificationRequirement(IntEnum):
    """Maps to WEBAUTHN_USER_VERIFICATION_REQUIREMENT_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L335
    """

    ANY = 0
    REQUIRED = 1
    PREFERRED = 2
    DISCOURAGED = 3


@unique
class WebAuthNAttestationConvoyancePreference(IntEnum):
    """Maps to WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L340
    """

    ANY = 0
    NONE = 1
    INDIRECT = 2
    DIRECT = 3


@unique
class WebAuthNAuthenticatorAttachment(IntEnum):
    """Maps to WEBAUTHN_AUTHENTICATOR_ATTACHMENT_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L330
    """

    ANY = 0
    PLATFORM = 1
    CROSS_PLATFORM = 2
    CROSS_PLATFORM_U2F_V2 = 3


@unique
class WebAuthNCTAPTransport(IntEnum):
    """Maps to WEBAUTHN_CTAP_TRANSPORT_USB_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L225
    """

    USB = 0x00000001
    NFC = 0x00000002
    BLE = 0x00000004
    TEST = 0x00000008
    INTERNAL = 0x00000010
    FLAGS_MASK = 0x0000001F


WEBAUTHN = ctypes.windll.webauthn
WEBAUTHN_API_VERSION = WEBAUTHN.WebAuthNGetApiVersionNumber()
# The following is derived from
# https://github.com/microsoft/webauthn/blob/master/webauthn.h#L37

WEBAUTHN.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.argtypes = [
    ctypes.POINTER(ctypes.c_bool)
]
WEBAUTHN.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.restype = ctypes.HRESULT

WEBAUTHN.WebAuthNAuthenticatorMakeCredential.argtypes = [
    HWND,
    ctypes.POINTER(WebAuthNRpEntityInformation),
    ctypes.POINTER(WebAuthNUserEntityInformation),
    ctypes.POINTER(WebAuthNCoseCredentialParameters),
    ctypes.POINTER(WebAuthNClientData),
    ctypes.POINTER(WebAuthNMakeCredentialOptions),
    ctypes.POINTER(ctypes.POINTER(WebAuthNCredentialAttestation)),
]
WEBAUTHN.WebAuthNAuthenticatorMakeCredential.restype = ctypes.HRESULT

WEBAUTHN.WebAuthNAuthenticatorGetAssertion.argtypes = [
    HWND,
    LPCWSTR,
    ctypes.POINTER(WebAuthNClientData),
    ctypes.POINTER(WebAuthNGetAssertionOptions),
    ctypes.POINTER(ctypes.POINTER(WebAuthNAssertion)),
]
WEBAUTHN.WebAuthNAuthenticatorGetAssertion.restype = ctypes.HRESULT

WEBAUTHN.WebAuthNFreeCredentialAttestation.argtypes = [
    ctypes.POINTER(WebAuthNCredentialAttestation)
]
WEBAUTHN.WebAuthNFreeAssertion.argtypes = [ctypes.POINTER(WebAuthNAssertion)]

WEBAUTHN.WebAuthNGetCancellationId.argtypes = [ctypes.POINTER(GUID)]
WEBAUTHN.WebAuthNGetCancellationId.restype = ctypes.HRESULT

WEBAUTHN.WebAuthNCancelCurrentOperation.argtypes = [ctypes.POINTER(GUID)]
WEBAUTHN.WebAuthNCancelCurrentOperation.restype = ctypes.HRESULT

WEBAUTHN.WebAuthNGetErrorName.argtypes = [ctypes.HRESULT]
WEBAUTHN.WebAuthNGetErrorName.restype = PCWSTR


WEBAUTHN_STRUCT_VERSIONS = {
    1: {
        "WebAuthNRpEntityInformation": 1,
        "WebAuthNUserEntityInformation": 1,
        "WebAuthNClientData": 1,
        "WebAuthNCoseCredentialParameter": 1,
        "WebAuthNCredential": 1,
        "WebAuthNCredentialEx": 1,
        "WebAuthNMakeCredentialOptions": 3,
        "WebAuthNGetAssertionOptions": 4,
        "WEBAUTHN_COMMON_ATTESTATION": 1,
        "WebAuthNCredentialAttestation": 3,
        "WebAuthNAssertion": 1,
    },
    2: {},
}  # type: Dict[int, Dict[str, int]]


def get_version(class_name):
    # type: (str) -> int
    """Get version of struct."""
    if class_name in WEBAUTHN_STRUCT_VERSIONS[WEBAUTHN_API_VERSION]:
        return WEBAUTHN_STRUCT_VERSIONS[WEBAUTHN_API_VERSION][class_name]

    return WEBAUTHN_STRUCT_VERSIONS[1][class_name]


def to_byte_array(pbyte, dword):
    # type: (PBYTE, DWORD) -> List[ctypes.c_byte]
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
        timeout=None,
    ):
        """Make credential using Windows WebAuthN API"""
        rp_info = WebAuthNRpEntityInformation(rp)
        user_info = WebAuthNUserEntityInformation(user)
        cose_cred_params = WebAuthNCoseCredentialParameters(key_params)
        webauthn_client_data = WebAuthNClientData(client_data)

        if options:
            rk = options.get("rk", True)
        else:
            rk = False

        # TODO: add support for extensions
        make_cred_options = WebAuthNMakeCredentialOptions(
            timeout,
            rk,
            WebAuthNAuthenticatorAttachment.CROSS_PLATFORM,
            WebAuthNUserVerificationRequirement.ANY,
            WebAuthNAttestationConvoyancePreference.DIRECT,
            exclude_list,
        )

        handle = ctypes.windll.user32.GetForegroundWindow()

        attestation_pointer = ctypes.POINTER(WebAuthNCredentialAttestation)()
        result = WEBAUTHN.WebAuthNAuthenticatorMakeCredential(
            handle,
            ctypes.byref(rp_info),
            ctypes.byref(user_info),
            ctypes.byref(cose_cred_params),
            ctypes.byref(webauthn_client_data),
            ctypes.byref(make_cred_options),
            ctypes.byref(attestation_pointer),
        )

        if result != 0:
            error = WEBAUTHN.WebAuthNGetErrorName(result)

            print("Failed to make credential using WebAuthN API: %s" % error)
            return sys.exit(1)

        return attestation_pointer.contents.to_attestation_object()

    def get_assertion(
        self, client_data, rp_id, allow_list, extensions, options, timeout
    ):
        """Get assertion using Windows WebAuthN API."""

        if options:
            uv = options.get("uv", False)
        else:
            uv = False

        webauthn_client_data = WebAuthNClientData(client_data)
        assertion_options = WebAuthNGetAssertionOptions(
            timeout,
            WebAuthNAuthenticatorAttachment.CROSS_PLATFORM,  # TODO: is this correct?
            WebAuthNUserVerificationRequirement.REQUIRED
            if uv
            else WebAuthNUserVerificationRequirement.ANY,
            allow_list,
        )

        handle = ctypes.windll.user32.GetForegroundWindow()
        assertion_pointer = ctypes.POINTER(WebAuthNAssertion)()
        result = WEBAUTHN.WebAuthNAuthenticatorGetAssertion(
            handle,
            rp_id,
            ctypes.pointer(webauthn_client_data),
            ctypes.pointer(assertion_options),
            ctypes.pointer(assertion_pointer),
        )

        if result != 0:
            error = WEBAUTHN.WebAuthNGetErrorName(result)

            print("Failed to make credential using WebAuthN API: %s" % error)
            return sys.exit(1)

        return [assertion_pointer.contents]
