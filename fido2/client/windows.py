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

from . import WebAuthnClient, _BaseClient, AssertionSelection, ClientError, _cbor_list
from .win_api import (
    WinAPI,
    WebAuthNAuthenticatorAttachment,
    WebAuthNUserVerificationRequirement,
    WebAuthNAttestationConveyancePreference,
    WebAuthNEnterpriseAttestation,
)
from ..rpid import verify_rp_id
from ..webauthn import (
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    AuthenticationExtensionsClientOutputs,
    AuthenticatorSelectionCriteria,
    AuthenticatorAttestationResponse,
    RegistrationResponse,
    AttestationConveyancePreference,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
    PublicKeyCredentialType,
    _as_cbor,
)
from ..ctap2 import AssertionResponse
from ..ctap2.extensions import (
    HMACGetSecretOutput,
    AuthenticatorExtensionsPRFOutputs,
    AuthenticatorExtensionsLargeBlobOutputs,
    CredentialPropertiesOutput,
)
from ..utils import _JsonDataObject

from typing import Callable, Sequence
import sys
import logging

logger = logging.getLogger(__name__)

_extension_output_types: dict[str, type[_JsonDataObject]] = {
    "hmacGetSecret": HMACGetSecretOutput,
    "prf": AuthenticatorExtensionsPRFOutputs,
    "largeBlob": AuthenticatorExtensionsLargeBlobOutputs,
    "credProps": CredentialPropertiesOutput,
}


def _wrap_ext(key, value):
    if key in _extension_output_types:
        return _extension_output_types[key].from_dict(value)
    return value


class WindowsClient(WebAuthnClient, _BaseClient):
    """Fido2Client-like class using the Windows WebAuthn API.

    Note: This class only works on Windows 10 19H1 or later. This is also when Windows
    started restricting access to FIDO devices, causing the standard client classes to
    require admin priveleges to run (unlike this one).

    The make_credential and get_assertion methods are intended to work as a drop-in
    replacement for the Fido2Client methods of the same name.

    :param str origin: The origin to use.
    :param verify: Function to verify an RP ID for a given origin.
    :param ctypes.wintypes.HWND handle: (optional) Window reference to use.
    """

    def __init__(
        self,
        origin: str,
        verify: Callable[[str, str], bool] = verify_rp_id,
        handle=None,
        allow_hmac_secret=False,
    ):
        super().__init__(origin, verify)
        self.api = WinAPI(handle, allow_hmac_secret=allow_hmac_secret)

        # TODO: Decide how to configure this list.
        self._enterprise_rpid_list: Sequence[str] | None = None

    @staticmethod
    def is_available() -> bool:
        return sys.platform == "win32" and WinAPI.version > 0

    def make_credential(self, options, event=None):
        """Create a credential using Windows WebAuthN APIs.

        :param options: PublicKeyCredentialCreationOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        options = PublicKeyCredentialCreationOptions.from_dict(options)

        rp_id = self._get_rp_id(options.rp.id)
        logger.debug(f"Register a new credential for RP ID: {rp_id}")
        self._verify_rp_id(rp_id)

        client_data = self._build_client_data(
            CollectedClientData.TYPE.CREATE, options.challenge
        )

        selection = options.authenticator_selection or AuthenticatorSelectionCriteria()

        enterprise_attestation = WebAuthNEnterpriseAttestation.NONE
        if options.attestation == AttestationConveyancePreference.ENTERPRISE:
            attestation = WebAuthNAttestationConveyancePreference.ANY
            if self._enterprise_rpid_list is not None:
                # Platform facilitated
                if options.rp.id in self._enterprise_rpid_list:
                    enterprise_attestation = (
                        WebAuthNEnterpriseAttestation.PLATFORM_MANAGED
                    )
            else:
                # Vendor facilitated
                enterprise_attestation = (
                    WebAuthNEnterpriseAttestation.VENDOR_FACILITATED
                )
        else:
            attestation = WebAuthNAttestationConveyancePreference.from_string(
                options.attestation or "none"
            )

        try:
            att_obj, extensions = self.api.make_credential(
                _as_cbor(options.rp),
                _as_cbor(options.user),
                _cbor_list(options.pub_key_cred_params),
                client_data,
                options.timeout or 0,
                selection.resident_key or ResidentKeyRequirement.DISCOURAGED,
                WebAuthNAuthenticatorAttachment.from_string(
                    selection.authenticator_attachment or "any"
                ),
                WebAuthNUserVerificationRequirement.from_string(
                    selection.user_verification or "discouraged"
                ),
                attestation,
                _cbor_list(options.exclude_credentials),
                options.extensions,
                event,
                enterprise_attestation,
            )
        except OSError as e:
            raise ClientError.ERR.OTHER_ERROR(e)

        logger.info("New credential registered")

        credential = att_obj.auth_data.credential_data
        assert credential is not None  # nosec

        return RegistrationResponse(
            raw_id=credential.credential_id,
            response=AuthenticatorAttestationResponse(client_data, att_obj),
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            client_extension_results=AuthenticationExtensionsClientOutputs(
                {k: _wrap_ext(k, v) for k, v in extensions.items()}
            ),
            type=PublicKeyCredentialType.PUBLIC_KEY,
        )

    def get_assertion(self, options, event=None):
        """Get assertion using Windows WebAuthN APIs.

        :param options: PublicKeyCredentialRequestOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        options = PublicKeyCredentialRequestOptions.from_dict(options)

        rp_id = self._get_rp_id(options.rp_id)
        logger.debug(f"Assert a credential for RP ID: {rp_id}")
        self._verify_rp_id(rp_id)

        client_data = self._build_client_data(
            CollectedClientData.TYPE.GET, options.challenge
        )

        try:
            (credential, auth_data, signature, user_id, extensions) = (
                self.api.get_assertion(
                    options.rp_id,
                    client_data,
                    options.timeout or 0,
                    WebAuthNAuthenticatorAttachment.ANY,
                    WebAuthNUserVerificationRequirement.from_string(
                        options.user_verification or "discouraged"
                    ),
                    _cbor_list(options.allow_credentials),
                    options.extensions,
                    event,
                )
            )
        except OSError as e:
            raise ClientError.ERR.OTHER_ERROR(e)

        user = {"id": user_id} if user_id else None
        return AssertionSelection(
            client_data,
            [
                AssertionResponse(
                    credential=credential,
                    auth_data=auth_data,
                    signature=signature,
                    user=user,
                )
            ],
            {k: _wrap_ext(k, v) for k, v in extensions.items()},
        )
