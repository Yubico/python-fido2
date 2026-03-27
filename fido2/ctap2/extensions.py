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

import abc
from dataclasses import dataclass
from enum import Enum, unique
from typing import Any, Mapping, cast

from _fido2_native.client import (
    NativeAuthenticationProcessor,
    NativeExtension,
    NativeRegistrationProcessor,
)

from ..utils import _JsonDataObject
from ..webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
)
from .base import AssertionResponse, AttestationResponse, Ctap2
from .pin import ClientPin, PinProtocol


class ExtensionProcessor(abc.ABC):
    """Base class for CTAP2 extension processing.

    See: :class:`RegistrationExtensionProcessor` and
    :class:`AuthenticationExtensionProcessor`.
    """

    def __init__(
        self,
        permissions: ClientPin.PERMISSION = ClientPin.PERMISSION(0),
        inputs: dict[str, Any] | None = None,
        outputs: dict[str, Any] | None = None,
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

    def prepare_inputs(self, pin_token: bytes | None) -> dict[str, Any] | None:
        "Prepare authenticator extension inputs, to be passed to the Authenenticator."
        return self._inputs

    def prepare_outputs(
        self,
        response: AttestationResponse,
        pin_token: bytes | None,
    ) -> dict[str, Any] | None:
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
        selected: PublicKeyCredentialDescriptor | None,
        pin_token: bytes | None,
    ) -> dict[str, Any] | None:
        "Prepare authenticator extension inputs, to be passed to the Authenenticator."
        return self._inputs

    def prepare_outputs(
        self,
        response: AssertionResponse,
        pin_token: bytes | None,
    ) -> dict[str, Any] | None:
        "Prepare client extension outputs, to be returned to the caller."
        return self._outputs


class Ctap2Extension(abc.ABC):
    """Base class for CTAP2 extensions.

    As of python-fido2 1.2 these instances can be used for multiple requests and
    should be invoked via the make_credential and get_assertion methods.
    Subclasses are instantiated for a single request, if the Authenticator supports
    the extension.
    """

    @abc.abstractmethod
    def is_supported(self, ctap: Ctap2) -> bool:
        """Whether or not the extension is supported by the authenticator."""

    def make_credential(
        self,
        ctap: Ctap2,
        options: PublicKeyCredentialCreationOptions,
        pin_protocol: PinProtocol | None,
    ) -> RegistrationExtensionProcessor | None:
        """Start client extension processing for registration."""
        return None

    def get_assertion(
        self,
        ctap: Ctap2,
        options: PublicKeyCredentialRequestOptions,
        pin_protocol: PinProtocol | None,
    ) -> AuthenticationExtensionProcessor | None:
        """Start client extension processing for authentication."""
        return None


class _NativeRegistrationProcessorWrapper(RegistrationExtensionProcessor):
    """Wraps a NativeRegistrationProcessor to match the Python interface."""

    def __init__(self, native: NativeRegistrationProcessor):
        super().__init__(permissions=ClientPin.PERMISSION(native.permissions))
        self._native = native

    def prepare_inputs(self, pin_token):
        return self._native.prepare_inputs(pin_token)

    def prepare_outputs(self, response, pin_token):
        return self._native.prepare_outputs(response, pin_token)


class _NativeAuthenticationProcessorWrapper(AuthenticationExtensionProcessor):
    """Wraps a NativeAuthenticationProcessor to match the Python interface."""

    def __init__(self, native: NativeAuthenticationProcessor):
        super().__init__(permissions=ClientPin.PERMISSION(native.permissions))
        self._native = native

    def prepare_inputs(self, selected, pin_token):
        return self._native.prepare_inputs(selected, pin_token)

    def prepare_outputs(self, response, pin_token):
        return self._native.prepare_outputs(response, pin_token)


class _NativeCtap2Extension(Ctap2Extension):
    """Base class for CTAP2 extensions backed by a native Rust implementation."""

    _native: NativeExtension

    def is_supported(self, ctap):
        return self._native.is_supported(ctap)

    def make_credential(self, ctap, options, pin_protocol):
        processor = self._native.make_credential(ctap, options, pin_protocol)
        if processor is not None:
            return _NativeRegistrationProcessorWrapper(processor)
        return None

    def get_assertion(self, ctap, options, pin_protocol):
        processor = self._native.get_assertion(ctap, options, pin_protocol)
        if processor is not None:
            return _NativeAuthenticationProcessorWrapper(processor)
        return None


@dataclass(eq=False, frozen=True)
class HMACGetSecretInput(_JsonDataObject):
    """Client inputs for hmac-secret."""

    salt1: bytes
    salt2: bytes | None = None


@dataclass(eq=False, frozen=True)
class HMACGetSecretOutput(_JsonDataObject):
    """Client outputs for hmac-secret."""

    output1: bytes
    output2: bytes | None = None


@dataclass(eq=False, frozen=True)
class AuthenticatorExtensionsPRFValues(_JsonDataObject):
    """Salt values for use with prf."""

    first: bytes
    second: bytes | None = None


@dataclass(eq=False, frozen=True)
class AuthenticatorExtensionsPRFInputs(_JsonDataObject):
    """Client inputs for prf."""

    eval: AuthenticatorExtensionsPRFValues | None = None
    eval_by_credential: Mapping[str, AuthenticatorExtensionsPRFValues] | None = None


@dataclass(eq=False, frozen=True)
class AuthenticatorExtensionsPRFOutputs(_JsonDataObject):
    """Client outputs for prf."""

    enabled: bool | None = None
    results: AuthenticatorExtensionsPRFValues | None = None


class HmacSecretExtension(_NativeCtap2Extension):
    """
    Implements the Pseudo-random function (prf) and the hmac-secret CTAP2 extensions.

    The hmac-secret extension is not directly available to clients by default, instead
    the prf extension is used.

    https://www.w3.org/TR/webauthn-3/#prf-extension

    https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#sctn-hmac-secret-extension

    :param allow_hmac_secret: Set to True to allow hmac-secret, in addition to prf.
    """

    _native_tag = "hmac_secret"
    NAME = "hmac-secret"
    MC_NAME = "hmac-secret-mc"
    SALT_LEN = 32

    def __init__(self, allow_hmac_secret=False):
        self._allow_hmac_secret = allow_hmac_secret
        self._native = NativeExtension.hmac_secret(allow_hmac_secret)


@dataclass(eq=False, frozen=True)
class AuthenticatorExtensionsLargeBlobInputs(_JsonDataObject):
    """Client inputs for largeBlob."""

    support: str | None = None
    read: bool | None = None
    write: bytes | None = None


@dataclass(eq=False, frozen=True)
class AuthenticatorExtensionsLargeBlobOutputs(_JsonDataObject):
    """Client outputs for largeBlob."""

    supported: bool | None = None
    blob: bytes | None = None
    written: bool | None = None


class LargeBlobExtension(_NativeCtap2Extension):
    """
    Implements the Large Blob storage (largeBlob) WebAuthn extension.

    https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension
    """

    _native_tag = "large_blob"
    NAME = "largeBlobKey"

    def __init__(self):
        self._native = NativeExtension.large_blob()


class CredBlobExtension(_NativeCtap2Extension):
    """
    Implements the Credential Blob (credBlob) CTAP2 extension.

    https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#sctn-credBlob-extension
    """

    _native_tag = "cred_blob"
    NAME = "credBlob"

    def __init__(self):
        self._native = NativeExtension.cred_blob()


class CredProtectExtension(_NativeCtap2Extension):
    """
    Implements the Credential Protection CTAP2 extension.

    https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#sctn-credProtect-extension
    """

    _native_tag = "cred_protect"

    @unique
    class POLICY(Enum):
        OPTIONAL = "userVerificationOptional"
        OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList"
        REQUIRED = "userVerificationRequired"

        @classmethod
        def str2int(cls, policy: str) -> int:
            return list(cls).index(cls(policy)) + 1

    NAME = "credProtect"

    def __init__(self):
        self._native = NativeExtension.cred_protect()


class MinPinLengthExtension(_NativeCtap2Extension):
    """
    Implements the Minimum PIN Length (minPinLength) CTAP2 extension.

    https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#sctn-minpinlength-extension
    """

    _native_tag = "min_pin_length"
    NAME = "minPinLength"

    def __init__(self):
        self._native = NativeExtension.min_pin_length()


class PinComplexityPolicyExtension(Ctap2Extension):
    """
    Implements the PIN Complexity Policy (pinComplexityPolicy) CTAP2 extension.

    https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#sctn-minpinlength-extension
    """

    NAME = "pinComplexityPolicy"

    def is_supported(self, ctap):
        return self.NAME in ctap.info.extensions

    def make_credential(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        if self.is_supported(ctap) and inputs.get(self.NAME) is True:
            return RegistrationExtensionProcessor(inputs={self.NAME: True})


@dataclass(eq=False, frozen=True)
class CredentialPropertiesOutput(_JsonDataObject):
    """Client outputs for credProps."""

    rk: bool | None = None


class CredPropsExtension(_NativeCtap2Extension):
    """
    Implements the Credential Properties (credProps) WebAuthn extension.

    https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension
    """

    _native_tag = "cred_props"
    NAME = "credProps"

    def __init__(self):
        self._native = NativeExtension.cred_props()


@dataclass(eq=False, frozen=True)
class PaymentCurrencyAmount(_JsonDataObject):
    currency: str
    value: str


@dataclass(eq=False, frozen=True)
class PaymentCredentialInstrument(_JsonDataObject):
    display_name: str
    icon: str
    icon_must_be_shown: bool = True


@dataclass(eq=False, frozen=True)
class AuthenticationExtensionsPaymentInputs(_JsonDataObject):
    """Client inputs for payment."""

    is_payment: bool | None = None
    rp_id: str | None = None
    top_origin: str | None = None
    payee_name: str | None = None
    payee_origin: str | None = None
    total: PaymentCurrencyAmount | None = None
    instrument: PaymentCredentialInstrument | None = None


class ThirdPartyPaymentExtension(Ctap2Extension):
    """
    Implements the Third Party Payment (thirdPartyPayment) CTAP2.2 extension.

    https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-thirdPartyPayment-extension

    Note that most of the processing for the WebAuthn extension needs to be done by the
    client, see:
    https://www.w3.org/TR/secure-payment-confirmation/#sctn-collectedclientpaymentdata-dictionary

    As such, this extension is not included in the default extensions list, and should
    not be used without a client that supports the WebAuthn payment extension.
    """

    NAME = "thirdPartyPayment"

    def is_supported(self, ctap):
        return self.NAME in ctap.info.extensions

    def make_credential(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        data = AuthenticationExtensionsPaymentInputs.from_dict(
            cast(Mapping | None, inputs.get("payment"))
        )
        if self.is_supported(ctap) and data and data.is_payment:
            return RegistrationExtensionProcessor(inputs={self.NAME: True})

    def get_assertion(self, ctap, options, pin_protocol):
        inputs = options.extensions or {}
        data = AuthenticationExtensionsPaymentInputs.from_dict(
            cast(Mapping | None, inputs.get("payment"))
        )
        if self.is_supported(ctap) and data and data.is_payment:
            return AuthenticationExtensionProcessor(inputs={self.NAME: True})


_DEFAULT_EXTENSIONS = [
    HmacSecretExtension(),
    LargeBlobExtension(),
    CredBlobExtension(),
    CredProtectExtension(),
    MinPinLengthExtension(),
    CredPropsExtension(),
]
