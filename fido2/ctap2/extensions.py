# Copyright (c) 2020 Yubico AB
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

from .base import AttestationResponse, AssertionResponse, Ctap2
from .pin import ClientPin, PinProtocol
from .blob import LargeBlobs
from ..utils import sha256, websafe_encode
from ..webauthn import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)
from enum import Enum, unique
from typing import Dict, Tuple, Any, Optional
import abc
import warnings


class Ctap2Extension(abc.ABC):
    """Base class for Ctap2 extensions.
    Subclasses are instantiated for a single request, if the Authenticator supports
    the extension.
    """

    NAME: str = None  # type: ignore

    def __init__(self, ctap: Ctap2):
        self.ctap = ctap
        # TODO: Pass options and selected to the various methods that need them instead
        self._create_options: PublicKeyCredentialCreationOptions
        self._get_options: PublicKeyCredentialRequestOptions
        self._selected: Optional[PublicKeyCredentialDescriptor]

    def is_supported(self) -> bool:
        """Whether or not the extension is supported by the authenticator."""
        return self.NAME in self.ctap.info.extensions

    def get_create_permissions(self, inputs: Dict[str, Any]) -> ClientPin.PERMISSION:
        return ClientPin.PERMISSION(0)

    def process_create_input(self, inputs: Dict[str, Any]) -> Any:
        """Returns a value to include in the authenticator extension input,
        or None.
        """
        return None

    def process_create_input_with_permissions(
        self, inputs: Dict[str, Any]
    ) -> Tuple[Any, ClientPin.PERMISSION]:
        warnings.warn(
            "This method is deprecated, use get_create_permissions.", DeprecationWarning
        )

        return self.process_create_input(inputs), self.get_create_permissions(inputs)

    def process_create_output(
        self,
        attestation_response: AttestationResponse,
        token: Optional[str],
        pin_protocol: Optional[PinProtocol],
    ) -> Optional[Dict[str, Any]]:
        """Return client extension output given attestation_response, or None."""
        return None

    def get_get_permissions(self, inputs: Dict[str, Any]) -> ClientPin.PERMISSION:
        return ClientPin.PERMISSION(0)

    def process_get_input(self, inputs: Dict[str, Any]) -> Any:
        """Returns a value to include in the authenticator extension input,
        or None.
        """
        return None

    def process_get_input_with_permissions(
        self, inputs: Dict[str, Any]
    ) -> Tuple[Any, ClientPin.PERMISSION]:
        warnings.warn(
            "This method is deprecated, use get_get_permissions.", DeprecationWarning
        )
        return self.process_get_input(inputs), self.get_get_permissions(inputs)

    def process_get_output(
        self,
        assertion_response: AssertionResponse,
        token: Optional[str],
        pin_protocol: Optional[PinProtocol],
    ) -> Optional[Dict[str, Any]]:
        """Return client extension output given assertion_response, or None."""
        return None


def _prf_salt(secret):
    return sha256(b"WebAuthn PRF\0" + secret)


class HmacSecretExtension(Ctap2Extension):
    """
    Implements the hmac-secret CTAP2 extension.
    """

    NAME = "hmac-secret"
    SALT_LEN = 32

    def __init__(self, ctap, pin_protocol=None, allow_hmac_secret=False):
        super().__init__(ctap)
        self.pin_protocol = pin_protocol
        self._allow_hmac_secret = allow_hmac_secret

    def process_create_input(self, inputs):
        if self.is_supported():
            if inputs.get("hmacCreateSecret") is True and self._allow_hmac_secret:
                self.prf = False
                return True
            elif inputs.get("prf") is not None:
                self.prf = True
                return True

    def process_create_output(self, attestation_response, *args):
        enabled = attestation_response.auth_data.extensions.get(self.NAME, False)
        if self.prf:
            return {"prf": {"enabled": enabled}}
        else:
            return {"hmacCreateSecret": enabled}

    def process_get_input(self, inputs):
        if not self.is_supported():
            return

        data = inputs.get("prf")
        if data:
            secrets = data.get("eval")
            by_creds = data.get("evalByCredential")
            if by_creds:
                # Make sure all keys are valid IDs from allow_credentials
                allow_list = self._get_options.allow_credentials
                if not allow_list:
                    raise ValueError("evalByCredentials requires allowCredentials")
                ids = {websafe_encode(c.id) for c in allow_list}
                if not ids.issuperset(by_creds):
                    raise ValueError("evalByCredentials contains invalid key")
                if self._selected:
                    key = websafe_encode(self._selected.id)
                    if key in by_creds:
                        secrets = by_creds[key]

            if not secrets:
                return

            salts = (
                _prf_salt(secrets["first"]),
                _prf_salt(secrets["second"]) if "second" in secrets else b"",
            )
            self.prf = True
        else:
            data = inputs.get("hmacGetSecret")
            if not data or not self._allow_hmac_secret:
                return
            salts = data["salt1"], data.get("salt2", b"")
            self.prf = False

        if not (
            len(salts[0]) == HmacSecretExtension.SALT_LEN
            and (not salts[1] or len(salts[1]) == HmacSecretExtension.SALT_LEN)
        ):
            raise ValueError("Invalid salt length")

        client_pin = ClientPin(self.ctap, self.pin_protocol)
        key_agreement, self.shared_secret = client_pin._get_shared_secret()
        if self.pin_protocol is None:
            self.pin_protocol = client_pin.protocol

        salt_enc = self.pin_protocol.encrypt(self.shared_secret, salts[0] + salts[1])
        salt_auth = self.pin_protocol.authenticate(self.shared_secret, salt_enc)

        return {
            1: key_agreement,
            2: salt_enc,
            3: salt_auth,
            4: self.pin_protocol.VERSION,
        }

    def process_get_output(self, assertion_response, *args):
        value = assertion_response.auth_data.extensions.get(self.NAME)

        decrypted = self.pin_protocol.decrypt(self.shared_secret, value)
        output1 = decrypted[: HmacSecretExtension.SALT_LEN]
        output2 = decrypted[HmacSecretExtension.SALT_LEN :]

        if self.prf:
            results = {"first": output1}
            if output2:
                results["second"] = output2
            return {"prf": {"results": results}}
        else:
            results = {"output1": output1}
            if output2:
                results["output2"] = output2
            return {"hmacGetSecret": results}


class LargeBlobExtension(Ctap2Extension):
    """
    Implements the Large Blob WebAuthn extension.
    """

    NAME = "largeBlobKey"

    def is_supported(self):
        return super().is_supported() and self.ctap.info.options.get("largeBlobs")

    def process_create_input(self, inputs):
        data = inputs.get("largeBlob", {})
        if data:
            if "read" in data or "write" in data:
                raise ValueError("Invalid set of parameters")
            is_supported = self.is_supported()
            if data.get("support") == "required" and not is_supported:
                raise ValueError("Authenticator does not support large blob storage")
            return True

    def process_create_output(self, attestation_response, *args):
        return {
            "largeBlob": {"supported": attestation_response.large_blob_key is not None}
        }

    def get_get_permissions(self, inputs):
        if inputs.get("largeBlob", {}).get("write"):
            return ClientPin.PERMISSION.LARGE_BLOB_WRITE
        return ClientPin.PERMISSION(0)

    def process_get_input(self, inputs):
        data = inputs.get("largeBlob", {})
        if data:
            if "support" in data or ("read" in data and "write" in data):
                raise ValueError("Invalid set of parameters")
            if not self.is_supported():
                raise ValueError("Authenticator does not support large blob storage")
            if data.get("read") is True:
                self._action = True
            else:
                self._action = data.get("write")
        return True if data else None

    def process_get_output(self, assertion_response, token, pin_protocol):
        blob_key = assertion_response.large_blob_key
        if self._action is True:  # Read
            large_blobs = LargeBlobs(self.ctap)
            blob = large_blobs.get_blob(blob_key)
            return {"largeBlob": {"blob": blob}}
        elif self._action:  # Write
            large_blobs = LargeBlobs(self.ctap, pin_protocol, token)
            large_blobs.put_blob(blob_key, self._action)
            return {"largeBlob": {"written": True}}


class CredBlobExtension(Ctap2Extension):
    """
    Implements the Credential Blob CTAP2 extension.
    """

    NAME = "credBlob"

    def process_create_input(self, inputs):
        if self.is_supported():
            blob = inputs.get("credBlob")
            assert self.ctap.info.max_cred_blob_length is not None  # nosec
            if blob and len(blob) <= self.ctap.info.max_cred_blob_length:
                return blob

    def process_get_input(self, inputs):
        if self.is_supported() and inputs.get("getCredBlob") is True:
            return True


class CredProtectExtension(Ctap2Extension):
    """
    Implements the Credential Protection CTAP2 extension.
    """

    @unique
    class POLICY(Enum):
        OPTIONAL = "userVerificationOptional"
        OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList"
        REQUIRED = "userVerificationRequired"

    ALWAYS_RUN = True
    NAME = "credProtect"

    def process_create_input(self, inputs):
        policy = inputs.get("credentialProtectionPolicy")
        if policy:
            index = list(CredProtectExtension.POLICY).index(
                CredProtectExtension.POLICY(policy)
            )
            enforce = inputs.get("enforceCredentialProtectionPolicy", False)
            if enforce and not self.is_supported() and index > 0:
                raise ValueError("Authenticator does not support Credential Protection")
            return index + 1


class MinPinLengthExtension(Ctap2Extension):
    """
    Implements the Minimum PIN Length CTAP2 extension.
    """

    NAME = "minPinLength"

    def is_supported(self):  # NB: There is no key in the extensions field.
        return "setMinPINLength" in self.ctap.info.options

    def process_create_input(self, inputs):
        if self.is_supported() and inputs.get(self.NAME) is True:
            return True


# NOTE: credProps is handled in fido2.client.Fido2Client
