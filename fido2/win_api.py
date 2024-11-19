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

from __future__ import annotations

from .utils import websafe_decode
from .webauthn import AttestationObject, AuthenticatorData, ResidentKeyRequirement
from enum import IntEnum, unique
from ctypes.wintypes import BOOL, DWORD, LONG, LPCWSTR, HWND, WORD
from threading import Thread
from typing import Mapping, Dict, Any, Tuple

import ctypes
from ctypes import WinDLL  # type: ignore
from ctypes import LibraryLoader

import warnings


windll = LibraryLoader(WinDLL)


PBYTE = ctypes.POINTER(ctypes.c_ubyte)  # Different from wintypes.PBYTE, which is signed
PCWSTR = ctypes.c_wchar_p


class BytesProperty:
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
        setattr(instance, self.cbName, len(value) if value is not None else 0)
        setattr(instance, self.pbName, ctypes.cast(value or 0, PBYTE))


class GUID(ctypes.Structure):
    """GUID Type in C++."""

    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    def __str__(self):
        return "{%08X-%04X-%04X-%04X-%012X}" % (
            self.Data1,
            self.Data2,
            self.Data3,
            self.Data4[0] * 256 + self.Data4[1],
            self.Data4[2] * (256**5)
            + self.Data4[3] * (256**4)
            + self.Data4[4] * (256**3)
            + self.Data4[5] * (256**2)
            + self.Data4[6] * 256
            + self.Data4[7],
        )


class WebAuthNCoseCredentialParameter(ctypes.Structure):
    """Maps to WEBAUTHN_COSE_CREDENTIAL_PARAMETER Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L185

    :param Dict[str, Any] cred_params: Dict of Credential parameters.
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("pwszCredentialType", LPCWSTR),
        ("lAlg", LONG),
    ]

    def __init__(self, cred_params):
        self.dwVersion = get_version(self.__class__.__name__)
        self.pwszCredentialType = cred_params["type"]
        self.lAlg = cred_params["alg"]


class WebAuthNCoseCredentialParameters(ctypes.Structure):
    """Maps to WEBAUTHN_COSE_CREDENTIAL_PARAMETERS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L191

    :param List[Dict[str, Any]] params: List of Credential parameter dicts.
    """

    _fields_ = [
        ("cCredentialParameters", DWORD),
        ("pCredentialParameters", ctypes.POINTER(WebAuthNCoseCredentialParameter)),
    ]

    def __init__(self, params):
        self.cCredentialParameters = len(params)
        self.pCredentialParameters = (WebAuthNCoseCredentialParameter * len(params))(
            *(WebAuthNCoseCredentialParameter(param) for param in params)
        )


class WebAuthNClientData(ctypes.Structure):
    """Maps to WEBAUTHN_CLIENT_DATA Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L153

    :param bytes client_data: ClientData serialized as JSON bytes.
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbClientDataJSON", DWORD),
        ("pbClientDataJSON", PBYTE),
        ("pwszHashAlgId", LPCWSTR),
    ]

    json = BytesProperty("ClientDataJSON")

    def __init__(self, client_data):
        self.dwVersion = get_version(self.__class__.__name__)
        self.json = client_data
        self.pwszHashAlgId = "SHA-256"


class WebAuthNRpEntityInformation(ctypes.Structure):
    """Maps to WEBAUTHN_RP_ENTITY_INFORMATION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L98

    :param Dict[str, Any] rp: Dict of RP information.
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("pwszId", PCWSTR),
        ("pwszName", PCWSTR),
        ("pwszIcon", PCWSTR),
    ]

    def __init__(self, rp):
        self.dwVersion = get_version(self.__class__.__name__)
        self.pwszId = rp["id"]
        self.pwszName = rp["name"]
        self.pwszIcon = rp.get("icon")


class WebAuthNUserEntityInformation(ctypes.Structure):
    """Maps to WEBAUTHN_USER_ENTITY_INFORMATION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L127

    :param Dict[str, Any] user: Dict of User information.
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
        self.dwVersion = get_version(self.__class__.__name__)
        self.id = user["id"]
        self.pwszName = user["name"]
        self.pwszIcon = user.get("icon")
        self.pwszDisplayName = user.get("displayName")


class WebAuthNCredentialEx(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL_EX Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L250

    :param Dict[str, Any] cred: Dict of Credential Descriptor data.
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
        self.dwVersion = get_version(self.__class__.__name__)
        self.id = cred["id"]
        self.pwszCredentialType = cred["type"]
        self.dwTransports = WebAuthNCTAPTransport[cred.get("transport", "ANY")]


class WebAuthNCredentialList(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL_LIST Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L261

    :param List[Dict[str, Any]] credentials: List of dict of
        Credential Descriptor data.
    """

    _fields_ = [
        ("cCredentials", DWORD),
        ("ppCredentials", ctypes.POINTER(ctypes.POINTER(WebAuthNCredentialEx))),
    ]

    def __init__(self, credentials):
        self.cCredentials = len(credentials)
        self.ppCredentials = (ctypes.POINTER(WebAuthNCredentialEx) * len(credentials))(
            *(ctypes.pointer(WebAuthNCredentialEx(cred)) for cred in credentials)
        )


class WebAuthNHmacSecretSalt(ctypes.Structure):

    _fields_ = [
        ("cbFirst", DWORD),
        ("pbFirst", PBYTE),
        ("cbSecond", DWORD),
        ("pbSecond", PBYTE),
    ]

    first = BytesProperty("First")
    second = BytesProperty("Second")

    def __init__(self, first, second=None):
        self.first = first
        self.second = second


class WebAuthNCredWithHmacSecretSalt(ctypes.Structure):

    _fields_ = [
        ("cbCredID", DWORD),
        ("pbCredID", PBYTE),
        ("pHmacSecretSalt", ctypes.POINTER(WebAuthNHmacSecretSalt)),
    ]

    cred_id = BytesProperty("CredID")

    def __init__(self, cred_id, salt):
        self.cred_id = cred_id
        self.salt = ctypes.pointer(salt)


class WebAuthNHmacSecretSaltValues(ctypes.Structure):

    _fields_ = [
        ("pGlobalHmacSalt", ctypes.POINTER(WebAuthNHmacSecretSalt)),
        ("cCredWithHmacSecretSaltList", DWORD),
        ("pCredWithHmacSecretSaltList", ctypes.POINTER(WebAuthNCredWithHmacSecretSalt)),
    ]

    def __init__(self, global_salt, credential_salts=[]):
        if global_salt:
            self.pGlobalHmacSalt = ctypes.pointer(global_salt)

        self.cCredWithHmacSecretSaltList = len(credential_salts)
        self.pCredWithHmacSecretSaltList = (
            WebAuthNCredWithHmacSecretSalt * len(credential_salts)
        )(*credential_salts)


class WebAuthNCredProtectExtensionIn(ctypes.Structure):
    """Maps to WEBAUTHN_CRED_PROTECT_EXTENSION_IN Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L493
    """

    _fields_ = [
        ("dwCredProtect", DWORD),
        ("bRequireCredProtect", BOOL),
    ]

    def __init__(self, cred_protect, require_cred_protect):
        self.dwCredProtect = cred_protect
        self.bRequireCredProtect = require_cred_protect


class WebAuthNCredBlobExtension(ctypes.Structure):
    _fields_ = [
        ("cbCredBlob", DWORD),
        ("pbCredBlob", PBYTE),
    ]

    cred_blob = BytesProperty("CredBlob")

    def __init__(self, blob):
        self.cred_blob = blob


class WebAuthNExtension(ctypes.Structure):
    """Maps to WEBAUTHN_EXTENSION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L317
    """

    _fields_ = [
        ("pwszExtensionIdentifier", LPCWSTR),
        ("cbExtension", DWORD),
        ("pvExtension", PBYTE),
    ]

    def __init__(self, identifier, value):
        self.pwszExtensionIdentifier = identifier
        self.cbExtension = ctypes.sizeof(value)
        self.pvExtension = ctypes.cast(ctypes.pointer(value), PBYTE)


class WebAuthNExtensions(ctypes.Structure):
    """Maps to WEBAUTHN_EXTENSIONS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L324
    """

    _fields_ = [
        ("cExtensions", DWORD),
        ("pExtensions", ctypes.POINTER(WebAuthNExtension)),
    ]

    def __init__(self, extensions):
        self.cExtensions = len(extensions)
        self.pExtensions = (WebAuthNExtension * len(extensions))(*extensions)


class WebAuthNCredential(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L212

    :param Dict[str, Any] cred: Dict of Credential Descriptor data.
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbId", DWORD),
        ("pbId", PBYTE),
        ("pwszCredentialType", LPCWSTR),
    ]

    id = BytesProperty("Id")

    def __init__(self, cred):
        self.id = cred["id"]
        self.pwszCredentialType = cred["type"]

    @property
    def descriptor(self):
        return {"type": self.pwszCredentialType, "id": self.id}


class WebAuthNCredentials(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIALS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L219

    :param List[Dict[str, Any]] credentials: List of dict of
        Credential Descriptor data.
    """

    _fields_ = [
        ("cCredentials", DWORD),
        ("pCredentials", ctypes.POINTER(WebAuthNCredential)),
    ]

    def __init__(self, credentials):
        self.cCredentials = len(credentials)
        self.pCredentials = (WebAuthNCredential * len(credentials))(
            *(WebAuthNCredential(cred) for cred in credentials)
        )


class CtapCborHybridStorageLinkedData(ctypes.Structure):
    """Maps to CTAPCBOR_HYBRID_STORAGE_LINKED_DATA Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L356
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbContactId", DWORD),
        ("pbContactId", PBYTE),
        ("cbLinkId", DWORD),
        ("pbLinkId", PBYTE),
        ("cbLinkSecret", DWORD),
        ("pbLinkSecret", PBYTE),
        ("cbPublicKey", DWORD),
        ("pbPublicKey", PBYTE),
        ("pwszAuthenticatorName", PCWSTR),
        ("wEncodedTunnelServerDomain", WORD),
    ]  # TODO

    contact_id = BytesProperty("ContactId")
    link_id = BytesProperty("LinkId")
    link_secret = BytesProperty("LinkSecret")
    public_key = BytesProperty("PublicKey")


class WebAuthNGetAssertionOptions(ctypes.Structure):
    """Maps to WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L452

    :param int timeout: Time that the operation is expected to complete within.
        This is used as guidance, and can be overridden by the platform.
    :param WebAuthNAuthenticatorAttachment attachment: Platform vs Cross-Platform
        Authenticators.
    :param WebAuthNUserVerificationRequirement user_verification_requirement: User
        Verification Requirement.
    :param List[Dict[str,Any]] credentials: Allowed Credentials List.
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
        ("pbU2fAppId", ctypes.POINTER(BOOL)),
        ("pCancellationId", ctypes.POINTER(GUID)),
        ("pAllowCredentialList", ctypes.POINTER(WebAuthNCredentialList)),
        ("dwCredLargeBlobOperation", DWORD),
        ("cbCredLargeBlob", DWORD),
        ("pbCredLargeBlob", PBYTE),
        ("pHmacSecretSaltValues", ctypes.POINTER(WebAuthNHmacSecretSaltValues)),
        ("bBrowserInPrivateMode", BOOL),
        ("pLinkedDevice", ctypes.POINTER(CtapCborHybridStorageLinkedData)),
        ("bAutoFill", BOOL),
        ("cbJsonExt", DWORD),
        ("pbJsonExt", PBYTE),
    ]

    cred_large_blob = BytesProperty("CredLargeBlob")
    json_ext = BytesProperty("JsonExt")

    def __init__(
        self,
        timeout,
        attachment,
        user_verification_requirement,
        credentials,
        cancellationId,
        cred_large_blob_operation,
        cred_large_blob,
        hmac_secret_salts=None,
        extensions=None,
        flags=0,
        u2f_appid=None,
        u2f_appid_used=None,
    ):
        self.dwVersion = get_version(self.__class__.__name__)
        self.dwTimeoutMilliseconds = timeout
        self.dwAuthenticatorAttachment = attachment
        self.dwUserVerificationRequirement = user_verification_requirement
        self.dwFlags = flags

        if extensions:
            self.Extensions = WebAuthNExtensions(extensions)

        if self.dwVersion >= 2:
            self.pwszU2fAppId = u2f_appid
            if u2f_appid_used is not None:
                self.pbU2fAppId = ctypes.pointer(u2f_appid_used)

        if self.dwVersion >= 3:
            self.pCancellationId = cancellationId

        if self.dwVersion >= 4:
            clist = WebAuthNCredentialList(credentials)
            self.pAllowCredentialList = ctypes.pointer(clist)
        else:
            self.CredentialList = WebAuthNCredentials(credentials)

        if self.dwVersion >= 5:
            self.dwCredLargeBlobOperation = cred_large_blob_operation
            self.cred_large_blob = cred_large_blob

        if self.dwVersion >= 6 and hmac_secret_salts:
            self.pHmacSecretSaltValues = ctypes.pointer(hmac_secret_salts)


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
        ("Extensions", WebAuthNExtensions),
        ("cbCredLargeBlob", DWORD),
        ("pbCredLargeBlob", PBYTE),
        ("dwCredLargeBlobStatus", DWORD),
        ("pHmacSecret", ctypes.POINTER(WebAuthNHmacSecretSalt)),
        ("dwUsedTransports", DWORD),
        ("cbUnsignedExtensionOutputs", DWORD),
        ("pbUnsignedExtensionOutputs", PBYTE),
    ]

    auth_data = BytesProperty("AuthenticatorData")
    signature = BytesProperty("Signature")
    user_id = BytesProperty("UserId")
    cred_large_blob = BytesProperty("CredLargeBlob")
    unsigned_extension_outputs = BytesProperty("UnsignedExtensionOutputs")

    def __del__(self):
        WEBAUTHN.WebAuthNFreeAssertion(ctypes.byref(self))


class WebAuthNMakeCredentialOptions(ctypes.Structure):
    """maps to WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L394

    :param int timeout: Time that the operation is expected to complete within.This
        is used as guidance, and can be overridden by the platform.
    :param bool require_resident_key: Require key to be resident or not.
    :param WebAuthNAuthenticatorAttachment attachment: Platform vs Cross-Platform
        Authenticators.
    :param WebAuthNUserVerificationRequirement user_verification_requirement: User
        Verification Requirement.
    :param WebAuthNAttestationConveyancePreference attestation_convoyence:
        Attestation Conveyance Preference.
    :param List[Dict[str,Any]] credentials: Credentials used for exclusion.
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
        ("dwEnterpriseAttestation", DWORD),
        ("dwLargeBlobSupport", DWORD),
        ("bPreferResidentKey", BOOL),
        ("bBrowserInPrivateMode", BOOL),
        ("bEnablePrf", BOOL),
        ("pLinkedDevice", ctypes.POINTER(CtapCborHybridStorageLinkedData)),
        ("cbJsonExt", DWORD),
        ("pbJsonExt", PBYTE),
    ]

    json_ext = BytesProperty("JsonExt")

    def __init__(
        self,
        timeout,
        require_resident_key,
        attachment,
        user_verification_requirement,
        attestation_convoyence,
        credentials,
        cancellationId,
        enterprise_attestation,
        large_blob_support,
        prefer_resident_key,
        enable_prf=False,
        extensions=None,
    ):
        self.dwVersion = get_version(self.__class__.__name__)
        self.dwTimeoutMilliseconds = timeout
        self.bRequireResidentKey = require_resident_key
        self.dwAuthenticatorAttachment = attachment
        self.dwUserVerificationRequirement = user_verification_requirement
        self.dwAttestationConveyancePreference = attestation_convoyence

        if extensions:
            self.Extensions = WebAuthNExtensions(extensions)

        if self.dwVersion >= 2:
            self.pCancellationId = cancellationId

        if self.dwVersion >= 3:
            self.pExcludeCredentialList = ctypes.pointer(
                WebAuthNCredentialList(credentials)
            )
        else:
            self.CredentialList = WebAuthNCredentials(credentials)

        if self.dwVersion >= 4:
            self.dwEnterpriseAttestation = enterprise_attestation
            self.dwLargeBlobSupport = large_blob_support
            self.bPreferResidentKey = prefer_resident_key

        if self.dwVersion >= 6:
            self.bEnablePrf = enable_prf


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
        ("bEpAtt", BOOL),
        ("bLargeBlobSupported", BOOL),
        ("bResidentKey", BOOL),
        ("bPrfEnabled", BOOL),
        ("cbUnsignedExtensionOutputs", DWORD),
        ("pbUnsignedExtensionOutputs", PBYTE),
    ]

    auth_data = BytesProperty("AuthenticatorData")
    attestation = BytesProperty("Attestation")
    attestation_object = BytesProperty("AttestationObject")
    credential_id = BytesProperty("CredentialId")
    unsigned_extension_outputs = BytesProperty("UnsignedExtensionOutputs")

    def __del__(self):
        WEBAUTHN.WebAuthNFreeCredentialAttestation(ctypes.byref(self))


class _FromString(object):
    @classmethod
    def from_string(cls, value):
        return getattr(cls, value.upper().replace("-", "_"))


@unique
class WebAuthNUserVerificationRequirement(_FromString, IntEnum):
    """Maps to WEBAUTHN_USER_VERIFICATION_REQUIREMENT_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L335
    """

    ANY = 0
    REQUIRED = 1
    PREFERRED = 2
    DISCOURAGED = 3


@unique
class WebAuthNAttestationConveyancePreference(_FromString, IntEnum):
    """Maps to WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L340
    """

    ANY = 0
    NONE = 1
    INDIRECT = 2
    DIRECT = 3


@unique
class WebAuthNAuthenticatorAttachment(_FromString, IntEnum):
    """Maps to WEBAUTHN_AUTHENTICATOR_ATTACHMENT_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L330
    """

    ANY = 0
    PLATFORM = 1
    CROSS_PLATFORM = 2
    CROSS_PLATFORM_U2F_V2 = 3


@unique
class WebAuthNCTAPTransport(_FromString, IntEnum):
    """Maps to WEBAUTHN_CTAP_TRANSPORT_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L225
    """

    ANY = 0x00000000
    USB = 0x00000001
    NFC = 0x00000002
    BLE = 0x00000004
    TEST = 0x00000008
    INTERNAL = 0x00000010
    FLAGS_MASK = 0x0000001F


@unique
class WebAuthNEnterpriseAttestation(_FromString, IntEnum):
    """Maps to WEBAUTHN_ENTERPRISE_ATTESTATION_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L401
    """

    NONE = 0
    VENDOR_FACILITATED = 1
    PLATFORM_MANAGED = 2


@unique
class WebAuthNLargeBlobSupport(_FromString, IntEnum):
    """Maps to WEBAUTHN_LARGE_BLOB_SUPPORT_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L405
    """

    NONE = 0
    REQUIRED = 1
    PREFERRED = 2


@unique
class WebAuthNLargeBlobOperation(_FromString, IntEnum):
    """Maps to WEBAUTHN_LARGE_BLOB_OPERATION_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L478
    """

    NONE = 0
    GET = 1
    SET = 2
    DELETE = 3


@unique
class WebAuthNUserVerification(_FromString, IntEnum):
    """Maps to WEBAUTHN_USER_VERIFICATION_*.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L482
    """

    ANY = 0
    OPTIONAL = 1
    OPTIONAL_WITH_CREDENTIAL_ID_LIST = 2
    REQUIRED = 3


HRESULT = ctypes.HRESULT  # type: ignore
WEBAUTHN = windll.webauthn  # type: ignore
WEBAUTHN_API_VERSION = WEBAUTHN.WebAuthNGetApiVersionNumber()
# The following is derived from
# https://github.com/microsoft/webauthn/blob/master/webauthn.h#L37

WEBAUTHN.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.argtypes = [
    ctypes.POINTER(ctypes.c_bool)
]
WEBAUTHN.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.restype = HRESULT

WEBAUTHN.WebAuthNAuthenticatorMakeCredential.argtypes = [
    HWND,
    ctypes.POINTER(WebAuthNRpEntityInformation),
    ctypes.POINTER(WebAuthNUserEntityInformation),
    ctypes.POINTER(WebAuthNCoseCredentialParameters),
    ctypes.POINTER(WebAuthNClientData),
    ctypes.POINTER(WebAuthNMakeCredentialOptions),
    ctypes.POINTER(ctypes.POINTER(WebAuthNCredentialAttestation)),
]
WEBAUTHN.WebAuthNAuthenticatorMakeCredential.restype = HRESULT

WEBAUTHN.WebAuthNAuthenticatorGetAssertion.argtypes = [
    HWND,
    LPCWSTR,
    ctypes.POINTER(WebAuthNClientData),
    ctypes.POINTER(WebAuthNGetAssertionOptions),
    ctypes.POINTER(ctypes.POINTER(WebAuthNAssertion)),
]
WEBAUTHN.WebAuthNAuthenticatorGetAssertion.restype = HRESULT

WEBAUTHN.WebAuthNFreeCredentialAttestation.argtypes = [
    ctypes.POINTER(WebAuthNCredentialAttestation)
]
WEBAUTHN.WebAuthNFreeAssertion.argtypes = [ctypes.POINTER(WebAuthNAssertion)]

WEBAUTHN.WebAuthNGetCancellationId.argtypes = [ctypes.POINTER(GUID)]
WEBAUTHN.WebAuthNGetCancellationId.restype = HRESULT

WEBAUTHN.WebAuthNCancelCurrentOperation.argtypes = [ctypes.POINTER(GUID)]
WEBAUTHN.WebAuthNCancelCurrentOperation.restype = HRESULT

WEBAUTHN.WebAuthNGetErrorName.argtypes = [HRESULT]
WEBAUTHN.WebAuthNGetErrorName.restype = PCWSTR


WEBAUTHN_STRUCT_VERSIONS: Mapping[int, Mapping[str, int]] = {
    1: {
        "WebAuthNRpEntityInformation": 1,
        "WebAuthNUserEntityInformation": 1,
        "WebAuthNClientData": 1,
        "WebAuthNCoseCredentialParameter": 1,
        "WebAuthNCredential": 1,
        "WebAuthNCredentialEx": 1,
        "WebAuthNMakeCredentialOptions": 3,
        "WebAuthNGetAssertionOptions": 4,
        "WebAuthNCommonAttestation": 1,
        "WebAuthNCredentialAttestation": 3,
        "WebAuthNAssertion": 1,
    },
    2: {},
    3: {
        "WebAuthNMakeCredentialOptions": 4,
        "WebAuthNGetAssertionOptions": 5,
        "WebAuthNCredentialAttestation": 4,
        "WebAuthNAssertion": 2,
    },
    4: {
        "WebAuthNMakeCredentialOptions": 5,
        "WebAuthNGetAssertionOptions": 6,
        "WebAuthNAssertion": 3,
        "WebAuthNCredentialDetails": 1,  # Not implemented
    },
    5: {
        "WebAuthNCredentialDetails": 2,
    },
    6: {
        "WebAuthNMakeCredentialOptions": 6,
        "WebAuthNCredentialAttestation": 5,
        "WebAuthNAssertion": 4,
    },
    7: {
        "WebAuthNMakeCredentialOptions": 7,
        "WebAuthNGetAssertionOptions": 7,
        "WebAuthNCredentialAttestation": 6,
        "WebAuthNAssertion": 5,
    },
}


def get_version(class_name: str) -> int:
    """Get version of struct.

    :param str class_name: Struct class name.
    :returns: Version of Struct to use.
    :rtype: int
    """
    for api_version in range(WEBAUTHN_API_VERSION, 0, -1):
        if (
            api_version in WEBAUTHN_STRUCT_VERSIONS
            and class_name in WEBAUTHN_STRUCT_VERSIONS[api_version]
        ):
            return WEBAUTHN_STRUCT_VERSIONS[api_version][class_name]
    raise ValueError("Unknown class name")


class CancelThread(Thread):
    def __init__(self, event):
        super().__init__()
        self.daemon = True
        self._completed = False
        self.event = event
        self.guid = GUID()
        WEBAUTHN.WebAuthNGetCancellationId(ctypes.byref(self.guid))

    def run(self):
        self.event.wait()
        if not self._completed:
            WEBAUTHN.WebAuthNCancelCurrentOperation(ctypes.byref(self.guid))

    def complete(self):
        self._completed = True
        self.event.set()
        self.join()


# Not implemented: Platform credentials support


class WinAPI:
    """Implementation of Microsoft's WebAuthN APIs.

    :param ctypes.HWND handle: Window handle to use for API calls.
    """

    version = WEBAUTHN_API_VERSION

    def __init__(self, handle=None, return_extensions=False, allow_hmac_secret=False):
        self.handle = handle or windll.user32.GetForegroundWindow()
        # TODO 2.0: Remove return_extensions and always return them
        if not return_extensions:
            warnings.warn(
                "WinAPI will start returning extension outputs in the next major "
                "version, to opt in to this behaivor now, set return_extensions=True.",
                DeprecationWarning,
            )
        self._return_extensions = return_extensions
        self._allow_hmac_secret = allow_hmac_secret

    def get_error_name(self, winerror):
        """Returns an error name given an error HRESULT value.

        :param int winerror: Windows error code from an OSError.
        :return: An error name.
        :rtype: str

        Example:
            try:
                api.make_credential(*args, **kwargs)
            except OSError as e:
                print(api.get_error_name(e.winerror))
        """
        return WEBAUTHN.WebAuthNGetErrorName(winerror)

    def make_credential(
        self,
        rp,
        user,
        pub_key_cred_params,
        client_data,
        timeout=0,
        resident_key=False,
        platform_attachment=WebAuthNAuthenticatorAttachment.ANY,
        user_verification=WebAuthNUserVerificationRequirement.ANY,
        attestation=WebAuthNAttestationConveyancePreference.DIRECT,
        exclude_credentials=None,
        extensions=None,
        event=None,
        enterprise_attestation=WebAuthNEnterpriseAttestation.NONE,
    ) -> Tuple[AttestationObject, Dict[str, Any]]:
        """Make credential using Windows WebAuthN API.

        :param Dict[str,Any] rp: Relying Party Entity data.
        :param Dict[str,Any] user: User Entity data.
        :param List[Dict[str,Any]] pub_key_cred_params: List of
            PubKeyCredentialParams data.
        :param bytes client_data: ClientData JSON.
        :param int timeout: (optional) Timeout value, in ms.
        :param bool resident_key: (optional) Require resident key, default: False.
        :param WebAuthNAuthenticatorAttachment platform_attachment: (optional)
            Authenticator Attachment, default: any.
        :param WebAuthNUserVerificationRequirement user_verification: (optional)
            User Verification Requirement, default: any.
        :param WebAuthNAttestationConveyancePreference attestation: (optional)
            Attestation Conveyance Preference, default: direct.
        :param List[Dict[str,Any]] exclude_credentials: (optional) List of
            PublicKeyCredentialDescriptor of previously registered credentials.
        :param Any extensions: Currently not supported.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        # TODO 2.0: Require resident_key be ResidentKeyRequirement
        if isinstance(resident_key, bool):
            warnings.warn(
                "Passing resident_key as a bool is deprecated. "
                "Use ResidentKeyRequirement instead.",
                DeprecationWarning,
            )

        win_extensions = []
        large_blob_support = WebAuthNLargeBlobSupport.NONE
        enable_prf = False
        if extensions:
            if "credentialProtectionPolicy" in extensions:
                win_extensions.append(
                    WebAuthNExtension(
                        "credProtect",
                        WebAuthNCredProtectExtensionIn(
                            WebAuthNUserVerification.from_string(
                                extensions["credentialProtectionPolicy"]
                            ),
                            extensions.get("enforceCredentialProtectionPolicy", False),
                        ),
                    )
                )
            if "credBlob" in extensions:
                win_extensions.append(
                    WebAuthNExtension(
                        "credBlob",
                        WebAuthNCredBlobExtension(extensions["credBlob"]),
                    )
                )
            if "largeBlob" in extensions:
                large_blob_support = WebAuthNLargeBlobSupport.from_string(
                    extensions["largeBlob"].get("support", "none")
                )
            if extensions.get("minPinLength", True):
                win_extensions.append(WebAuthNExtension("minPinLength", BOOL(True)))
            if "prf" in extensions:
                resident_key = True  # Windows requires resident key for hmac-secret
                enable_prf = True
                win_extensions.append(WebAuthNExtension("hmac-secret", BOOL(True)))
            elif "hmacCreateSecret" in extensions and self._allow_hmac_secret:
                resident_key = True  # Windows requires resident key for hmac-secret
                win_extensions.append(WebAuthNExtension("hmac-secret", BOOL(True)))
        else:
            extensions = {}

        if event:
            t = CancelThread(event)
            t.start()

        attestation_pointer = ctypes.POINTER(WebAuthNCredentialAttestation)()
        WEBAUTHN.WebAuthNAuthenticatorMakeCredential(
            self.handle,
            ctypes.byref(WebAuthNRpEntityInformation(rp)),
            ctypes.byref(WebAuthNUserEntityInformation(user)),
            ctypes.byref(WebAuthNCoseCredentialParameters(pub_key_cred_params)),
            ctypes.byref(WebAuthNClientData(client_data)),
            ctypes.byref(
                WebAuthNMakeCredentialOptions(
                    timeout,
                    resident_key in (True, ResidentKeyRequirement.REQUIRED),
                    platform_attachment,
                    user_verification,
                    attestation,
                    exclude_credentials or [],
                    ctypes.pointer(t.guid) if event else None,
                    enterprise_attestation,
                    large_blob_support,
                    resident_key == ResidentKeyRequirement.PREFERRED,
                    enable_prf,
                    win_extensions,
                )
            ),
            ctypes.byref(attestation_pointer),
        )
        if event:
            t.complete()

        obj = attestation_pointer.contents
        att_obj = AttestationObject(obj.attestation_object)

        extensions_out = att_obj.auth_data.extensions or {}
        extension_outputs = {}
        if extensions.get("credProps"):
            extension_outputs["credProps"] = {"rk": bool(obj.bResidentKey)}
        if "hmac-secret" in extensions_out:
            if enable_prf:
                extension_outputs["prf"] = {"enabled": extensions_out["hmac-secret"]}
            else:
                extension_outputs["hmacCreateSecret"] = extensions_out["hmac-secret"]
        if "largeBlob" in extensions:
            extension_outputs["largeBlob"] = {
                "supported": bool(obj.bLargeBlobSupported)
            }

        if self._return_extensions:
            return att_obj, extension_outputs
        else:
            return att_obj  # type: ignore

    def get_assertion(
        self,
        rp_id,
        client_data,
        timeout=0,
        platform_attachment=WebAuthNAuthenticatorAttachment.ANY,
        user_verification=WebAuthNUserVerificationRequirement.ANY,
        allow_credentials=None,
        extensions=None,
        event=None,
    ) -> Tuple[Dict[str, Any], AuthenticatorData, bytes, bytes, Dict[str, Any]]:
        """Get assertion using Windows WebAuthN API.

        :param str rp_id: Relying Party ID string.
        :param bytes client_data: ClientData JSON.
        :param int timeout: (optional) Timeout value, in ms.
        :param WebAuthNAuthenticatorAttachment platform_attachment: (optional)
            Authenticator Attachment, default: any.
        :param WebAuthNUserVerificationRequirement user_verification: (optional)
            User Verification Requirement, default: any.
        :param List[Dict[str,Any]] allow_credentials: (optional) List of
            PublicKeyCredentialDescriptor of previously registered credentials.
        :param Any extensions: Currently not supported.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        flags = 0
        large_blob = None
        large_blob_operation = WebAuthNLargeBlobOperation.NONE
        hmac_secret_salts = None
        win_extensions = []
        u2f_appid = None
        u2f_appid_used = BOOL(False)
        if extensions:
            if extensions.get("appid"):
                u2f_appid = extensions["appid"]
            if extensions.get("getCredBlob"):
                win_extensions.append(WebAuthNExtension("credBlob", BOOL(True)))
            if "largeBlob" in extensions:
                if extensions["largeBlob"].get("read", False):
                    large_blob_operation = WebAuthNLargeBlobOperation.GET
                else:
                    large_blob = extensions["largeBlob"]["write"]
                    large_blob_operation = WebAuthNLargeBlobOperation.SET
            if "prf" in extensions:
                global_salts = extensions["prf"].get("eval")
                cred_salts = extensions["prf"].get("evalByCredential", {})
                hmac_secret_salts = WebAuthNHmacSecretSaltValues(
                    WebAuthNHmacSecretSalt(**global_salts) if global_salts else None,
                    [
                        WebAuthNCredWithHmacSecretSalt(
                            websafe_decode(cred_id),
                            WebAuthNHmacSecretSalt(**salts),
                        )
                        for cred_id, salts in cred_salts.items()
                    ],
                )
            elif "hmacGetSecret" in extensions and self._allow_hmac_secret:
                flags |= 0x00100000
                salts = extensions["hmacGetSecret"]
                hmac_secret_salts = WebAuthNHmacSecretSaltValues(
                    WebAuthNHmacSecretSalt(salts["salt1"], salts.get("salt2"))
                )

        if event:
            t = CancelThread(event)
            t.start()

        assertion_pointer = ctypes.POINTER(WebAuthNAssertion)()
        WEBAUTHN.WebAuthNAuthenticatorGetAssertion(
            self.handle,
            rp_id,
            ctypes.byref(WebAuthNClientData(client_data)),
            ctypes.byref(
                WebAuthNGetAssertionOptions(
                    timeout,
                    platform_attachment,
                    user_verification,
                    allow_credentials or [],
                    ctypes.pointer(t.guid) if event else None,
                    large_blob_operation,
                    large_blob,
                    hmac_secret_salts,
                    win_extensions,
                    flags,
                    u2f_appid,
                    u2f_appid_used,
                )
            ),
            ctypes.byref(assertion_pointer),
        )

        if event:
            t.complete()

        obj = assertion_pointer.contents
        auth_data = AuthenticatorData(obj.auth_data)

        extension_outputs: Dict[str, Any] = {}

        if u2f_appid and obj.dwVersion >= 2:
            extension_outputs["appid"] = bool(u2f_appid_used.value)

        if extensions:
            if hmac_secret_salts and obj.dwVersion >= 3:
                secret = obj.pHmacSecret.contents
                if "prf" in extensions:
                    result = {"first": secret.first}
                    if secret.second:
                        result["second"] = secret.second
                    extension_outputs["prf"] = {"results": result}
                else:
                    result = {"output1": secret.first}
                    if secret.second:
                        result["output2"] = secret.second
                    extension_outputs["hmacGetSecret"] = result
            if obj.dwCredLargeBlobStatus != 0:
                if extensions["largeBlob"].get("read", False):
                    extension_outputs["largeBlob"] = {"blob": obj.cred_large_blob}
                else:
                    extension_outputs["largeBlob"] = {
                        "written": obj.dwCredLargeBlobStatus == 1
                    }

        if self._return_extensions:
            return (
                obj.Credential.descriptor,
                auth_data,
                obj.signature,
                obj.user_id,
                extension_outputs,
            )
        else:
            return (
                obj.Credential.descriptor,
                auth_data,
                obj.signature,
                obj.user_id,
            )  # type: ignore
