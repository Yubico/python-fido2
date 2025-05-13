# Copyright (c) 2019 Onica Group LLC.
# Modified work Copyright 2019 Yubico.
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

import ctypes
from ctypes import LibraryLoader, WinDLL  # type: ignore
from ctypes.wintypes import BOOL, DWORD, HWND, LONG, LPCWSTR, WORD
from enum import IntEnum, unique
from typing import Any, Mapping, Sequence

# Not implemented: Platform credentials support


windll = LibraryLoader(WinDLL)


PBYTE = ctypes.POINTER(ctypes.c_ubyte)  # Different from wintypes.PBYTE, which is signed
PCWSTR = ctypes.c_wchar_p
PVOID = ctypes.c_void_p


class BytesProperty:
    """Property for structs storing byte arrays as DWORD + PBYTE.

    Allows for easy reading/writing to struct fields using Python bytes objects.
    """

    def __init__(self, name: str):
        self.cbName = "cb" + name
        self.pbName = "pb" + name

    def __get__(self, instance, owner):
        return bytes(
            bytearray(getattr(instance, self.pbName)[: getattr(instance, self.cbName)])
        )

    def __set__(self, instance, value: bytes | None):
        ln = len(value) if value else 0
        buffer = ctypes.create_string_buffer(value) if value else 0
        setattr(instance, self.cbName, ln)
        setattr(instance, self.pbName, ctypes.cast(buffer, PBYTE))


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


class _FromString:
    @classmethod
    def from_string(cls, value: str):
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


class WebAuthNCoseCredentialParameter(ctypes.Structure):
    """Maps to WEBAUTHN_COSE_CREDENTIAL_PARAMETER Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L185

    :param cred_params: Dict of Credential parameters.
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("pwszCredentialType", LPCWSTR),
        ("lAlg", LONG),
    ]

    def __init__(self, cred_params: Mapping[str, Any]):
        self.dwVersion = get_version(self.__class__.__name__)
        self.pwszCredentialType = cred_params["type"]
        self.lAlg = cred_params["alg"]


class WebAuthNCoseCredentialParameters(ctypes.Structure):
    """Maps to WEBAUTHN_COSE_CREDENTIAL_PARAMETERS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L191

    :param params: List of Credential parameter dicts.
    """

    _fields_ = [
        ("cCredentialParameters", DWORD),
        ("pCredentialParameters", ctypes.POINTER(WebAuthNCoseCredentialParameter)),
    ]

    def __init__(self, params: Sequence[Mapping[str, Any]]):
        self.cCredentialParameters = len(params)
        self.pCredentialParameters = (WebAuthNCoseCredentialParameter * len(params))(
            *(WebAuthNCoseCredentialParameter(param) for param in params)
        )


class WebAuthNClientData(ctypes.Structure):
    """Maps to WEBAUTHN_CLIENT_DATA Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L153

    :param client_data_json: ClientData serialized as JSON bytes.
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbClientDataJSON", DWORD),
        ("pbClientDataJSON", PBYTE),
        ("pwszHashAlgId", LPCWSTR),
    ]

    client_data_json = BytesProperty("ClientDataJSON")

    def __init__(self, client_data_json: bytes):
        self.dwVersion = get_version(self.__class__.__name__)
        self.client_data_json = client_data_json
        self.pwszHashAlgId = "SHA-256"


class WebAuthNRpEntityInformation(ctypes.Structure):
    """Maps to WEBAUTHN_RP_ENTITY_INFORMATION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L98

    :param rp: Dict of RP information.
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("pwszId", PCWSTR),
        ("pwszName", PCWSTR),
        ("pwszIcon", PCWSTR),
    ]

    def __init__(self, rp: Mapping[str, Any]):
        self.dwVersion = get_version(self.__class__.__name__)
        self.pwszId = rp["id"]
        self.pwszName = rp["name"]
        self.pwszIcon = rp.get("icon")


class WebAuthNUserEntityInformation(ctypes.Structure):
    """Maps to WEBAUTHN_USER_ENTITY_INFORMATION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L127

    :param user: Dict of User information.
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

    def __init__(self, user: Mapping[str, Any]):
        self.dwVersion = get_version(self.__class__.__name__)
        self.id = user["id"]
        self.pwszName = user["name"]
        self.pwszIcon = user.get("icon")
        self.pwszDisplayName = user.get("displayName")


class WebAuthNCredentialEx(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL_EX Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L250

    :param cred: Dict of Credential Descriptor data.
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbId", DWORD),
        ("pbId", PBYTE),
        ("pwszCredentialType", LPCWSTR),
        ("dwTransports", DWORD),
    ]

    id = BytesProperty("Id")

    def __init__(self, cred: Mapping[str, Any]):
        self.dwVersion = get_version(self.__class__.__name__)
        self.id = cred["id"]
        self.pwszCredentialType = cred["type"]
        self.dwTransports = WebAuthNCTAPTransport[cred.get("transport", "ANY")]


class WebAuthNCredentialList(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL_LIST Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L261

    :param credentials: List of dict of Credential Descriptor data.
    """

    _fields_ = [
        ("cCredentials", DWORD),
        ("ppCredentials", ctypes.POINTER(ctypes.POINTER(WebAuthNCredentialEx))),
    ]

    def __init__(self, credentials: Sequence[Mapping[str, Any]]):
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

    def __init__(self, first: bytes, second: bytes | None = None):
        self.first = first
        self.second = second


class WebAuthNCredWithHmacSecretSalt(ctypes.Structure):
    _fields_ = [
        ("cbCredID", DWORD),
        ("pbCredID", PBYTE),
        ("pHmacSecretSalt", ctypes.POINTER(WebAuthNHmacSecretSalt)),
    ]

    cred_id = BytesProperty("CredID")

    def __init__(self, cred_id: bytes, salt: WebAuthNHmacSecretSalt):
        self.cred_id = cred_id
        self.pHmacSecretSalt = ctypes.pointer(salt)


class WebAuthNHmacSecretSaltValues(ctypes.Structure):
    _fields_ = [
        ("pGlobalHmacSalt", ctypes.POINTER(WebAuthNHmacSecretSalt)),
        ("cCredWithHmacSecretSaltList", DWORD),
        ("pCredWithHmacSecretSaltList", ctypes.POINTER(WebAuthNCredWithHmacSecretSalt)),
    ]

    def __init__(
        self,
        global_salt: WebAuthNHmacSecretSalt | None,
        credential_salts: Sequence[WebAuthNCredWithHmacSecretSalt] = [],
    ):
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

    def __init__(
        self, cred_protect: WebAuthNUserVerification, require_cred_protect: bool
    ):
        self.dwCredProtect = cred_protect
        self.bRequireCredProtect = require_cred_protect


class WebAuthNCredBlobExtension(ctypes.Structure):
    _fields_ = [
        ("cbCredBlob", DWORD),
        ("pbCredBlob", PBYTE),
    ]

    cred_blob = BytesProperty("CredBlob")

    def __init__(self, blob: bytes):
        self.cred_blob = blob


class WebAuthNExtension(ctypes.Structure):
    """Maps to WEBAUTHN_EXTENSION Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L317
    """

    _fields_ = [
        ("pwszExtensionIdentifier", LPCWSTR),
        ("cbExtension", DWORD),
        ("pvExtension", PVOID),
    ]

    def __init__(self, identifier: str, value: Any):
        self.pwszExtensionIdentifier = identifier
        self.cbExtension = ctypes.sizeof(value)
        self.pvExtension = ctypes.cast(ctypes.pointer(value), PVOID)


class WebAuthNExtensions(ctypes.Structure):
    """Maps to WEBAUTHN_EXTENSIONS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L324
    """

    _fields_ = [
        ("cExtensions", DWORD),
        ("pExtensions", ctypes.POINTER(WebAuthNExtension)),
    ]

    def __init__(self, extensions: Sequence[WebAuthNExtension]):
        self.cExtensions = len(extensions)
        self.pExtensions = (WebAuthNExtension * len(extensions))(*extensions)


class WebAuthNCredential(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIAL Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L212

    :param cred: Dict of Credential Descriptor data.
    """

    _fields_ = [
        ("dwVersion", DWORD),
        ("cbId", DWORD),
        ("pbId", PBYTE),
        ("pwszCredentialType", LPCWSTR),
    ]

    id = BytesProperty("Id")

    def __init__(self, cred: Mapping[str, Any]):
        self.id = cred["id"]
        self.pwszCredentialType = cred["type"]


class WebAuthNCredentials(ctypes.Structure):
    """Maps to WEBAUTHN_CREDENTIALS Struct.

    https://github.com/microsoft/webauthn/blob/master/webauthn.h#L219

    :param credentials: List of dict of Credential Descriptor data.
    """

    _fields_ = [
        ("cCredentials", DWORD),
        ("pCredentials", ctypes.POINTER(WebAuthNCredential)),
    ]

    def __init__(self, credentials: Sequence[Mapping[str, Any]]):
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

    :param timeout: Time that the operation is expected to complete within.
        This is used as guidance, and can be overridden by the platform.
    :param attachment: Platform vs Cross-Platform
        Authenticators.
    :param uv_requirement: User Verification Requirement.
    :param credentials: Allowed Credentials List.
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
        timeout: int = 0,
        attachment: int = WebAuthNAuthenticatorAttachment.ANY,
        uv_requirement: int = WebAuthNUserVerificationRequirement.DISCOURAGED,
        credentials: Sequence[Mapping[str, Any]] = [],
        cancellationId: GUID | None = None,
        cred_large_blob_operation: int = WebAuthNLargeBlobOperation.NONE,
        cred_large_blob: bytes | None = None,
        hmac_secret_salts: WebAuthNHmacSecretSaltValues | None = None,
        extensions: Sequence[WebAuthNExtension] = [],
        flags: int = 0,
        u2f_appid: str | None = None,
        u2f_appid_used: BOOL | None = None,
    ):
        self.dwVersion = get_version(self.__class__.__name__)
        self.dwTimeoutMilliseconds = timeout
        self.dwAuthenticatorAttachment = attachment
        self.dwUserVerificationRequirement = uv_requirement
        self.dwFlags = flags

        if extensions:
            self.Extensions = WebAuthNExtensions(extensions)

        if self.dwVersion >= 2:
            self.pwszU2fAppId = u2f_appid
            if u2f_appid_used is not None:
                self.pbU2fAppId = ctypes.pointer(u2f_appid_used)

        if self.dwVersion >= 3 and cancellationId:
            self.pCancellationId = ctypes.pointer(cancellationId)

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

    :param timeout: Time that the operation is expected to complete within.This
        is used as guidance, and can be overridden by the platform.
    :param require_resident_key: Require key to be resident or not.
    :param attachment: Platform vs Cross-Platform
        Authenticators.
    :param user_verification_requirement: User
        Verification Requirement.
    :param attestation_convoyence:
        Attestation Conveyance Preference.
    :param credentials: Credentials used for exclusion.
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
        timeout: int = 0,
        require_resident_key: bool = False,
        attachment: int = WebAuthNAuthenticatorAttachment.ANY,
        uv_requirement: int = WebAuthNUserVerificationRequirement.DISCOURAGED,
        attestation_convoyence: int = WebAuthNAttestationConveyancePreference.ANY,
        credentials: Sequence[Mapping[str, Any]] = [],
        cancellationId: GUID | None = None,
        enterprise_attestation: int = WebAuthNEnterpriseAttestation.NONE,
        large_blob_support: int = WebAuthNLargeBlobSupport.NONE,
        prefer_resident_key: bool = False,
        enable_prf: bool = False,
        extensions: Sequence[WebAuthNExtension] = [],
    ):
        self.dwVersion = get_version(self.__class__.__name__)
        self.dwTimeoutMilliseconds = timeout
        self.bRequireResidentKey = require_resident_key
        self.dwAuthenticatorAttachment = attachment
        self.dwUserVerificationRequirement = uv_requirement
        self.dwAttestationConveyancePreference = attestation_convoyence

        if extensions:
            self.Extensions = WebAuthNExtensions(extensions)

        if self.dwVersion >= 2 and cancellationId:
            self.pCancellationId = ctypes.pointer(cancellationId)

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
