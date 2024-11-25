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
from ..utils import sha256, websafe_encode, _JsonDataObject
from ..webauthn import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
)
from enum import Enum, unique
from dataclasses import dataclass
from typing import Dict, Tuple, Any, Optional, Mapping
import abc
import warnings


class ExtensionProcessor(abc.ABC):
    """Base class for CTAP2 extension processing.

    See: :class:`RegistrationExtensionProcessor` and
    :class:`AuthenticationExtensionProcessor`.
    """

    def __init__(
        self,
        permissions: ClientPin.PERMISSION = ClientPin.PERMISSION(0),
        inputs: Optional[Dict[str, Any]] = None,
        outputs: Optional[Dict[str, Any]] = None,
    ):
        self.permissions = permissions
        self._inputs = inputs
        self._outputs = outputs


class RegistrationExtensionProcessor(ExtensionProcessor):
    """Processing state for a CTAP2 extension, for single use.

    The ExtensionProcessor holds state and logic for client processing of an extension,
    for a registration (MakeCredential) call.

    :param permissions: PinUvAuthToken permissions required by the extension.
    :param inputs: Default authenticator inputs, if prepare_inputs is not overridden.
    :param outputs: Default client outputs, if prepare_outputs is not overridden.
    """

    def prepare_inputs(self, pin_token: Optional[bytes]) -> Optional[Dict[str, Any]]:
        "Prepare authenticator extension inputs, to be passed to the Authenenticator."
        return self._inputs

    def prepare_outputs(
        self,
        response: AttestationResponse,
        pin_token: Optional[bytes],
    ) -> Optional[Dict[str, Any]]:
        "Prepare client extension outputs, to be returned to the caller."
        return self._outputs


class AuthenticationExtensionProcessor(ExtensionProcessor):
    """Processing state for a CTAP2 extension, for single use.

    The ExtensionProcessor holds state and logic for client processing of an extension,
    for an authentication (GetAssertion) call.

    :param permissions: PinUvAuthToken permissions required by the extension.
    :param inputs: Default authenticator inputs, if prepare_inputs is not overridden.
    :param outputs: Default client outputs, if prepare_outputs is not overridden.
    """

    def prepare_inputs(
        self,
        selected: Optional[PublicKeyCredentialDescriptor],
        pin_token: Optional[bytes],
    ) -> Optional[Dict[str, Any]]:
        "Prepare authenticator extension inputs, to be passed to the Authenenticator."
        return self._inputs

    def prepare_outputs(
        self,
        response: AssertionResponse,
        pin_token: Optional[bytes],
    ) -> Optional[Dict[str, Any]]:
        "Prepare client extension outputs, to be returned to the caller."
        return self._outputs


# TODO 2.0: Make changes as described below
class Ctap2Extension(abc.ABC):
    """Base class for CTAP2 extensions.

    As of python-fido2 1.2 these instances can be used for multiple requests and
    should be invoked via the make_credential and get_assertion methods.
    Subclasses are instantiated for a single request, if the Authenticator supports
    the extension.

    From python-fido2 2.0 the following methods will be fully removed:
        get_create_permissions, process_create_input, process_create_output,
        process_create_input_with_permissions,
        get_get_permissions, process_get_input, process_get_output,
        process_get_input_with_permissions.

    The following changes will also be made:
        :func:`__init__` will no longer allow passing a ctap2 instance.
        :func:`is_supported` will require a ctap2 instance to be passed.
        :attr:`NAME` and :attr:`ctap` will be removed.
    """

    NAME: str = None  # type: ignore

    def __init__(self, ctap: Optional[Ctap2] = None):
        if ctap:
            warnings.warn(
                "Calling __init__ with a Ctap2 instance is deprecated.",
                DeprecationWarning,
            )

        self._ctap = ctap

    @property
    def ctap(self) -> Ctap2:
        ctap = self._ctap
        if not ctap:
            raise ValueError(
                "Accessed self.ctap when no ctap instance has been passed to __init__"
            )
        return ctap

    def is_supported(self, ctap: Optional[Ctap2] = None) -> bool:
        """Whether or not the extension is supported by the authenticator."""
        if not ctap:
            warnings.warn(
                "Calling is_supported without a Ctap2 instance is deprecated.",
                DeprecationWarning,
            )
        ctap = ctap or self._ctap
        if not ctap:
            raise ValueError("No Ctap2 instance available")
        return self.NAME in ctap.info.extensions

    def make_credential(
        self,
        ctap: Ctap2,
        options: PublicKeyCredentialCreationOptions,
        pin_protocol: Optional[PinProtocol],
    ) -> Optional[RegistrationExtensionProcessor]:
        """Start client extension processing for registration."""
        # This implementation is for LEGACY PURPOSES!
        # Subclasses should override this method instead of:
        #    process_create_input, process_create_output, and get_create_permissions
        warnings.warn(
            "This extension does not override make_credential, which is deprecated.",
            DeprecationWarning,
        )
        inputs = dict(options.extensions or {})
        self._ctap = ctap
        ext = self

        class Processor(RegistrationExtensionProcessor):
            def prepare_inputs(self, pin_token):
                processed = ext.process_create_input(inputs)
                self._has_input = processed is not None
                return {ext.NAME: processed} if self._has_input else None

            def prepare_outputs(self, response, pin_token):
                if self._has_input:
                    processed = ext.process_create_output(
                        response, pin_token, pin_protocol
                    )
                    return processed

        return Processor(self.get_create_permissions(inputs))

    def get_assertion(
        self,
        ctap: Ctap2,
        options: PublicKeyCredentialRequestOptions,
        pin_protocol: Optional[PinProtocol],
    ) -> Optional[AuthenticationExtensionProcessor]:
        """Start client extension processing for authentication."""
        # This implementation is for LEGACY PURPOSES!
        # Subclasses should override this method instead of:
        #    process_get_input, process_get_output, and get_get_permissions
        warnings.warn(
            "This extension does not override get_assertion, which is deprecated.",
            DeprecationWarning,
        )
        inputs = dict(options.extensions or {})
        self._ctap = ctap
        ext = self

        class Processor(AuthenticationExtensionProcessor):
            _has_input: bool

            def prepare_inputs(self, selected, pin_token):
                processed = ext.process_get_input(inputs)
                self._has_input = processed is not None
                return {ext.NAME: processed} if self._has_input else None

            def prepare_outputs(self, response, pin_token):
                if self._has_input:
                    return ext.process_get_output(response, pin_token, pin_protocol)

        return Processor(self.get_get_permissions(inputs))

    # TODO 2.0: Remove the remaining methods of this class
    def get_create_permissions(self, inputs: Dict[str, Any]) -> ClientPin.PERMISSION:
        """Get PinUvAuthToken permissions required for Registration.

        .. deprecated:: 1.2.0
           Implement :func:`make_credential` instead.
        """
        return ClientPin.PERMISSION(0)

    def process_create_input(self, inputs: Dict[str, Any]) -> Any:
        """Returns a value to include in the authenticator extension input,
        or None.

        .. deprecated:: 1.2.0
           Implement :func:`make_credential` instead.
        """
        return None

    def process_create_input_with_permissions(
        self, inputs: Dict[str, Any]
    ) -> Tuple[Any, ClientPin.PERMISSION]:
        """

        .. deprecated:: 1.2.0
           Implement :func:`make_credential` instead.
        """
        warnings.warn(
            "This method is deprecated, use make_credential().", DeprecationWarning
        )

        return self.process_create_input(inputs), self.get_create_permissions(inputs)

    def process_create_output(
        self,
        attestation_response: AttestationResponse,
        token: Optional[bytes],
        pin_protocol: Optional[PinProtocol],
    ) -> Optional[Dict[str, Any]]:
        """Return client extension output given attestation_response, or None.

        .. deprecated:: 1.2.0
           Implement :func:`make_credential` instead.
        """
        return None

    def get_get_permissions(self, inputs: Dict[str, Any]) -> ClientPin.PERMISSION:
        """
        .. deprecated:: 1.2.0
           Implement :func:`get_assertion` instead.
        """
        return ClientPin.PERMISSION(0)

    def process_get_input(self, inputs: Dict[str, Any]) -> Any:
        """Returns a value to include in the authenticator extension input,
        or None.

        .. deprecated:: 1.2.0
           Implement :func:`get_assertion` instead.
        """
        return None

    def process_get_input_with_permissions(
        self, inputs: Dict[str, Any]
    ) -> Tuple[Any, ClientPin.PERMISSION]:
        """
        .. deprecated:: 1.2.0
           Implement :func:`get_assertion` instead.
        """
        warnings.warn(
            "This method is deprecated, use get_assertion().", DeprecationWarning
        )
        return self.process_get_input(inputs), self.get_get_permissions(inputs)

    def process_get_output(
        self,
        assertion_response: AssertionResponse,
        token: Optional[bytes],
        pin_protocol: Optional[PinProtocol],
    ) -> Optional[Dict[str, Any]]:
        """Return client extension output given assertion_response, or None.

        .. deprecated:: 1.2.0
           Implement :func:`get_assertion` instead.
        """
        return None


@dataclass(eq=False, frozen=True)
class HMACGetSecretInput(_JsonDataObject):
    """Client inputs for hmac-secret."""

    salt1: bytes
    salt2: Optional[bytes] = None


@dataclass(eq=False, frozen=True)
class HMACGetSecretOutput(_JsonDataObject):
    """Client outputs for hmac-secret."""

    output1: bytes
    output2: Optional[bytes] = None


def _prf_salt(secret):
    return sha256(b"WebAuthn PRF\0" + secret)


@dataclass(eq=False, frozen=True)
class AuthenticatorExtensionsPRFValues(_JsonDataObject):
    """Salt values for use with prf."""

    first: bytes
    second: Optional[bytes] = None


@dataclass(eq=False, frozen=True)
class AuthenticatorExtensionsPRFInputs(_JsonDataObject):
    """Client inputs for prf."""

    eval: Optional[AuthenticatorExtensionsPRFValues] = None
    eval_by_credential: Optional[Mapping[str, AuthenticatorExtensionsPRFValues]] = None


@dataclass(eq=False, frozen=True)
class AuthenticatorExtensionsPRFOutputs(_JsonDataObject):
    """Client outputs for prf."""

    enabled: Optional[bool] = None
    results: Optional[AuthenticatorExtensionsPRFValues] = None


class HmacSecretExtension(Ctap2Extension):
    """
    Implements the Pseudo-random function (prf) and the hmac-secret CTAP2 extensions.

    The hmac-secret extension is not directly available to clients by default, instead
    the prf extension is used.

    https://www.w3.org/TR/webauthn-3/#prf-extension

    https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#sctn-hmac-secret-extension

    :param allow_hmac_secret: Set to True to allow hmac-secret, in addition to prf.
    """

    NAME = "hmac-secret"
    SALT_LEN = 32

    def __init__(self, ctap=None, pin_protocol=None, allow_hmac_secret=False):
        super().__init__(ctap)
        if pin_protocol:
            warnings.warn(
                "Initializing HmacSecretExtension with pin_protocol is deprecated, "
                "pin_protocol will be ignored.",
                DeprecationWarning,
            )
        self.pin_protocol = pin_protocol
        self._allow_hmac_secret = allow_hmac_secret

    def make_credential(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        prf = inputs.get("prf") is not None
        hmac = self._allow_hmac_secret and inputs.get("hmacCreateSecret") is True
        if self.is_supported(ctap) and (prf or hmac):

            class Processor(RegistrationExtensionProcessor):
                def prepare_inputs(self, pin_token):
                    return {HmacSecretExtension.NAME: True}

                def prepare_outputs(self, response, pin_token):
                    extensions = response.auth_data.extensions or {}
                    enabled = extensions.get(HmacSecretExtension.NAME, False)
                    if prf:
                        return {
                            "prf": AuthenticatorExtensionsPRFOutputs(enabled=enabled)
                        }
                    else:
                        return {"hmacCreateSecret": enabled}

            return Processor()

    def get_assertion(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        prf = AuthenticatorExtensionsPRFInputs.from_dict(inputs.get("prf"))
        hmac = (
            HMACGetSecretInput.from_dict(inputs.get("hmacGetSecret"))
            if self._allow_hmac_secret
            else None
        )

        if pin_protocol and self.is_supported(ctap) and (prf or hmac):
            client_pin = ClientPin(ctap, pin_protocol)
            key_agreement, shared_secret = client_pin._get_shared_secret()

            class Processing(AuthenticationExtensionProcessor):
                def prepare_inputs(self, selected, pin_token):
                    if prf:
                        secrets = prf.eval
                        by_creds = prf.eval_by_credential
                        if by_creds:
                            # Make sure all keys are valid IDs from allow_credentials
                            allow_list = options.allow_credentials
                            if not allow_list:
                                raise ValueError(
                                    "evalByCredentials requires allowCredentials"
                                )
                            ids = {websafe_encode(c.id) for c in allow_list}
                            if not ids.issuperset(by_creds):
                                raise ValueError(
                                    "evalByCredentials contains invalid key"
                                )
                            if selected:
                                key = websafe_encode(selected.id)
                                if key in by_creds:
                                    secrets = by_creds[key]

                        if not secrets:
                            return

                        salts = (
                            _prf_salt(secrets.first),
                            (
                                _prf_salt(secrets.second)
                                if secrets.second is not None
                                else b""
                            ),
                        )
                    else:
                        assert hmac is not None  # nosec
                        salts = hmac.salt1, hmac.salt2 or b""

                    if not (
                        len(salts[0]) == HmacSecretExtension.SALT_LEN
                        and (
                            not salts[1]
                            or len(salts[1]) == HmacSecretExtension.SALT_LEN
                        )
                    ):
                        raise ValueError("Invalid salt length")

                    salt_enc = pin_protocol.encrypt(shared_secret, salts[0] + salts[1])
                    salt_auth = pin_protocol.authenticate(shared_secret, salt_enc)

                    return {
                        HmacSecretExtension.NAME: {
                            1: key_agreement,
                            2: salt_enc,
                            3: salt_auth,
                            4: pin_protocol.VERSION,
                        }
                    }

                def prepare_outputs(self, response, pin_token):
                    extensions = response.auth_data.extensions or {}
                    value = extensions.get(HmacSecretExtension.NAME)

                    if value:
                        decrypted = client_pin.protocol.decrypt(shared_secret, value)
                        output1 = decrypted[: HmacSecretExtension.SALT_LEN]
                        output2 = decrypted[HmacSecretExtension.SALT_LEN :] or None
                    else:
                        return None

                    if prf:
                        return {
                            "prf": AuthenticatorExtensionsPRFOutputs(
                                results=AuthenticatorExtensionsPRFValues(
                                    output1, output2
                                )
                            )
                        }
                    else:
                        return {"hmacGetSecret": HMACGetSecretOutput(output1, output2)}

            return Processing()

    # TODO 2.0: Remove the remaining methods of this class
    def process_create_input(self, inputs):
        if self.is_supported() and inputs.get("hmacCreateSecret") is True:
            return True

    def process_create_output(self, attestation_response, *args, **kwargs):
        enabled = attestation_response.auth_data.extensions.get(self.NAME, False)
        return {"hmacCreateSecret": enabled}

    def process_get_input(self, inputs):
        if not self.is_supported():
            return

        get_secret = HMACGetSecretInput.from_dict(inputs.get("hmacGetSecret"))
        if not get_secret:
            return
        salts = get_secret.salt1, get_secret.salt2 or b""

        if not (
            len(salts[0]) == HmacSecretExtension.SALT_LEN
            and (not salts[1] or len(salts[1]) == HmacSecretExtension.SALT_LEN)
        ):
            raise ValueError("Invalid salt length")

        if not self._ctap:
            raise ValueError("No Ctap2 instance available")
        client_pin = ClientPin(self._ctap, self.pin_protocol)
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

    def process_get_output(self, assertion_response, *args, **kwargs):
        value = assertion_response.auth_data.extensions.get(self.NAME)

        assert self.pin_protocol is not None  # nosec
        decrypted = self.pin_protocol.decrypt(self.shared_secret, value)
        output1 = decrypted[: HmacSecretExtension.SALT_LEN]
        output2 = decrypted[HmacSecretExtension.SALT_LEN :] or None
        return {"hmacGetSecret": HMACGetSecretOutput(output1, output2)}


@dataclass(eq=False, frozen=True)
class AuthenticatorExtensionsLargeBlobInputs(_JsonDataObject):
    """Client inputs for largeBlob."""

    support: Optional[str] = None
    read: Optional[bool] = None
    write: Optional[bytes] = None


@dataclass(eq=False, frozen=True)
class AuthenticatorExtensionsLargeBlobOutputs(_JsonDataObject):
    """Client outputs for largeBlob."""

    supported: Optional[bool] = None
    blob: Optional[bytes] = None
    written: Optional[bool] = None


class LargeBlobExtension(Ctap2Extension):
    """
    Implements the Large Blob storage (largeBlob) WebAuthn extension.

    https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension
    """

    NAME = "largeBlobKey"

    def is_supported(self, ctap=None):
        ctap = ctap or self._ctap
        assert ctap is not None  # nosec
        return super().is_supported(ctap) and ctap.info.options.get("largeBlobs", False)

    def make_credential(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        data = AuthenticatorExtensionsLargeBlobInputs.from_dict(inputs.get("largeBlob"))
        if data:
            if data.read or data.write:
                raise ValueError("Invalid set of parameters")
            if data.support == "required" and not self.is_supported(ctap):
                raise ValueError("Authenticator does not support large blob storage")

            class Processor(RegistrationExtensionProcessor):
                def prepare_inputs(self, pin_token):
                    return {LargeBlobExtension.NAME: True}

                def prepare_outputs(self, response, pin_token):
                    return {
                        "largeBlob": AuthenticatorExtensionsLargeBlobOutputs(
                            supported=response.large_blob_key is not None
                        )
                    }

            return Processor()

    def get_assertion(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        data = AuthenticatorExtensionsLargeBlobInputs.from_dict(inputs.get("largeBlob"))
        if data:
            if data.support or (data.read and data.write):
                raise ValueError("Invalid set of parameters")
            if not self.is_supported(ctap):
                raise ValueError("Authenticator does not support large blob storage")

            class Processor(AuthenticationExtensionProcessor):
                def prepare_outputs(self, response, pin_token):
                    blob_key = response.large_blob_key
                    if blob_key:
                        if data.read:
                            large_blobs = LargeBlobs(ctap)
                            blob = large_blobs.get_blob(blob_key)
                            return {
                                "largeBlob": AuthenticatorExtensionsLargeBlobOutputs(
                                    blob=blob
                                )
                            }
                        elif data.write:
                            large_blobs = LargeBlobs(ctap, pin_protocol, pin_token)
                            large_blobs.put_blob(blob_key, data.write)
                            return {
                                "largeBlob": AuthenticatorExtensionsLargeBlobOutputs(
                                    written=True
                                )
                            }

            return Processor(
                (
                    ClientPin.PERMISSION.LARGE_BLOB_WRITE
                    if data.write
                    else ClientPin.PERMISSION(0)
                ),
                inputs={LargeBlobExtension.NAME: True},
            )

    # TODO 2.0: Remove the remaining methods of this class
    def process_create_input(self, inputs):
        data = AuthenticatorExtensionsLargeBlobInputs.from_dict(inputs.get("largeBlob"))
        if data:
            if data.read or data.write:
                raise ValueError("Invalid set of parameters")
            if data.support == "required" and not self.is_supported():
                raise ValueError("Authenticator does not support large blob storage")
            return True

    def process_create_output(self, attestation_response, *args, **kwargs):
        return {
            "largeBlob": AuthenticatorExtensionsLargeBlobOutputs(
                supported=attestation_response.large_blob_key is not None
            )
        }

    def get_get_permissions(self, inputs):
        data = AuthenticatorExtensionsLargeBlobInputs.from_dict(inputs.get("largeBlob"))
        if data and data.write:
            return ClientPin.PERMISSION.LARGE_BLOB_WRITE
        return ClientPin.PERMISSION(0)

    def process_get_input(self, inputs):
        data = AuthenticatorExtensionsLargeBlobInputs.from_dict(inputs.get("largeBlob"))
        if data:
            if data.support or (data.read and data.write):
                raise ValueError("Invalid set of parameters")
            if not self.is_supported():
                raise ValueError("Authenticator does not support large blob storage")
            if data.read:
                self._action = True
            else:
                self._action = data.write
            return True

    def process_get_output(self, assertion_response, token, pin_protocol):
        blob_key = assertion_response.large_blob_key
        if blob_key:
            if self._action is True:  # Read
                large_blobs = LargeBlobs(self.ctap)
                blob = large_blobs.get_blob(blob_key)
                return {"largeBlob": AuthenticatorExtensionsLargeBlobOutputs(blob=blob)}
            elif self._action:  # Write
                large_blobs = LargeBlobs(self.ctap, pin_protocol, token)
                large_blobs.put_blob(blob_key, self._action)
                return {
                    "largeBlob": AuthenticatorExtensionsLargeBlobOutputs(written=True)
                }


class CredBlobExtension(Ctap2Extension):
    """
    Implements the Credential Blob (credBlob) CTAP2 extension.

    https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#sctn-credBlob-extension
    """

    NAME = "credBlob"

    def make_credential(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        if self.is_supported():
            blob = inputs.get("credBlob")
            assert ctap.info.max_cred_blob_length is not None  # nosec
            if blob and len(blob) <= ctap.info.max_cred_blob_length:
                return RegistrationExtensionProcessor(inputs={self.NAME: blob})

    def get_assertion(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        if self.is_supported(ctap) and inputs.get("getCredBlob") is True:
            return AuthenticationExtensionProcessor(inputs={self.NAME: True})

    # TODO 2.0: Remove the remaining methods of this class
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

    https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#sctn-credProtect-extension
    """

    @unique
    class POLICY(Enum):
        OPTIONAL = "userVerificationOptional"
        OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList"
        REQUIRED = "userVerificationRequired"

    NAME = "credProtect"

    def make_credential(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        policy = inputs.get("credentialProtectionPolicy")
        if policy:
            index = list(CredProtectExtension.POLICY).index(
                CredProtectExtension.POLICY(policy)
            )
            enforce = inputs.get("enforceCredentialProtectionPolicy", False)
            if enforce and not self.is_supported(ctap) and index > 0:
                raise ValueError("Authenticator does not support Credential Protection")

            return RegistrationExtensionProcessor(inputs={self.NAME: index + 1})

    # TODO 2.0: Remove the remaining methods of this class
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
    Implements the Minimum PIN Length (minPinLength) CTAP2 extension.

    https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#sctn-minpinlength-extension
    """

    NAME = "minPinLength"

    def is_supported(self, ctap=None):
        # NB: There is no key in the extensions field.
        ctap = ctap or self._ctap
        assert ctap is not None  # nosec
        return "setMinPINLength" in ctap.info.options

    def make_credential(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        if self.is_supported(ctap) and inputs.get(self.NAME) is True:
            return RegistrationExtensionProcessor(inputs={self.NAME: True})

    # TODO 2.0: Remove the remaining methods of this class
    def process_create_input(self, inputs):
        if self.is_supported() and inputs.get(self.NAME) is True:
            return True


@dataclass(eq=False, frozen=True)
class CredentialPropertiesOutput(_JsonDataObject):
    """Client outputs for credProps."""

    rk: Optional[bool] = None


class CredPropsExtension(Ctap2Extension):
    """
    Implements the Credential Properties (credProps) WebAuthn extension.

    https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension
    """

    NAME = "credProps"

    def is_supported(self, ctap=None):  # NB: There is no key in the extensions field.
        return True

    def make_credential(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        if inputs.get(self.NAME) is True:
            selection = (
                options.authenticator_selection or AuthenticatorSelectionCriteria()
            )
            rk = selection.resident_key == ResidentKeyRequirement.REQUIRED or (
                selection.resident_key == ResidentKeyRequirement.PREFERRED
                and ctap.info.options.get("rk")
            )

            return RegistrationExtensionProcessor(
                outputs={self.NAME: CredentialPropertiesOutput(rk=rk)}
            )
