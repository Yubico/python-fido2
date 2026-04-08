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

import abc
import json
import logging
from enum import IntEnum, unique
from threading import Event, Timer
from typing import Any, Callable, Mapping, Sequence

from _fido2_native.client import ClientDataCollector as NativeClientDataCollector
from _fido2_native.client import NativeFido2Client

from ..ctap import CtapDevice, CtapError
from ..ctap2 import AssertionResponse, Info
from ..ctap2.pin import ClientPin
from ..hid import STATUS
from ..utils import websafe_encode
from ..webauthn import (
    AttestationObject,
    AuthenticationExtensionsClientOutputs,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorAttachment,
    AuthenticatorAttestationResponse,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialType,
    RegistrationResponse,
)

logger = logging.getLogger(__name__)


class _BytesEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return websafe_encode(o)
        return super().default(o)


class ClientError(Exception):
    """Base error raised by clients."""

    @unique
    class ERR(IntEnum):
        """Error codes for ClientError."""

        OTHER_ERROR = 1
        BAD_REQUEST = 2
        CONFIGURATION_UNSUPPORTED = 3
        DEVICE_INELIGIBLE = 4
        TIMEOUT = 5

        def __call__(self, cause=None):
            return ClientError(self, cause)

    def __init__(self, code, cause=None):
        self.code = ClientError.ERR(code)
        self.cause = cause

    def __repr__(self):
        r = "Client error: {0} - {0.name}".format(self.code)
        if self.cause:
            r += f" (cause: {self.cause})"
        return r


def _ctap2client_err(e, err_cls=ClientError):
    if e.code in [CtapError.ERR.CREDENTIAL_EXCLUDED, CtapError.ERR.NO_CREDENTIALS]:
        ce = ClientError.ERR.DEVICE_INELIGIBLE
    elif e.code in [
        CtapError.ERR.KEEPALIVE_CANCEL,
        CtapError.ERR.ACTION_TIMEOUT,
        CtapError.ERR.USER_ACTION_TIMEOUT,
    ]:
        ce = ClientError.ERR.TIMEOUT
    elif e.code in [
        CtapError.ERR.UNSUPPORTED_ALGORITHM,
        CtapError.ERR.UNSUPPORTED_OPTION,
        CtapError.ERR.KEY_STORE_FULL,
    ]:
        ce = ClientError.ERR.CONFIGURATION_UNSUPPORTED
    elif e.code in [
        CtapError.ERR.INVALID_COMMAND,
        CtapError.ERR.CBOR_UNEXPECTED_TYPE,
        CtapError.ERR.INVALID_CBOR,
        CtapError.ERR.MISSING_PARAMETER,
        CtapError.ERR.INVALID_OPTION,
        CtapError.ERR.PUAT_REQUIRED,
        CtapError.ERR.PIN_INVALID,
        CtapError.ERR.PIN_BLOCKED,
        CtapError.ERR.PIN_NOT_SET,
        CtapError.ERR.PIN_POLICY_VIOLATION,
        CtapError.ERR.PIN_TOKEN_EXPIRED,
        CtapError.ERR.PIN_AUTH_INVALID,
        CtapError.ERR.PIN_AUTH_BLOCKED,
        CtapError.ERR.REQUEST_TOO_LARGE,
        CtapError.ERR.OPERATION_DENIED,
    ]:
        ce = ClientError.ERR.BAD_REQUEST
    else:
        ce = ClientError.ERR.OTHER_ERROR

    return err_cls(ce, e)


class PinRequiredError(ClientError):
    """Raised when a call cannot be completed without providing PIN."""

    def __init__(
        self, code=ClientError.ERR.BAD_REQUEST, cause="PIN required but not provided"
    ):
        super().__init__(code, cause)


class AssertionSelection:
    """GetAssertion result holding one or more assertions.

    Since multiple assertions may be retured by Fido2Client.get_assertion, this result
    is returned which can be used to select a specific response to get.
    """

    def __init__(
        self,
        client_data: CollectedClientData,
        assertions: Sequence[AssertionResponse],
        extension_outputs_list: Sequence[Mapping[str, Any]],
    ):
        self._client_data = client_data
        self._assertions = assertions
        self._extension_outputs_list = extension_outputs_list

    def get_assertions(self) -> Sequence[AssertionResponse]:
        """Get the raw AssertionResponses available to inspect before selecting one."""
        return self._assertions

    def get_response(self, index: int) -> AuthenticationResponse:
        """Get a single response."""
        assertion = self._assertions[index]
        extension_outputs = self._extension_outputs_list[index]

        return AuthenticationResponse(
            raw_id=assertion.credential["id"],
            response=AuthenticatorAssertionResponse(
                client_data=self._client_data,
                authenticator_data=assertion.auth_data,
                signature=assertion.signature,
                user_handle=assertion.user["id"] if assertion.user else None,
            ),
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            client_extension_results=AuthenticationExtensionsClientOutputs(
                extension_outputs
            ),
            type=PublicKeyCredentialType.PUBLIC_KEY,
        )


class WebAuthnClient(abc.ABC):
    """Base class for a WebAuthn client, supporting registration and authentication."""

    @abc.abstractmethod
    def make_credential(
        self,
        options: PublicKeyCredentialCreationOptions,
        event: Event | None = None,
    ) -> RegistrationResponse:
        """Creates a credential.

        :param options: PublicKeyCredentialCreationOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_assertion(
        self,
        options: PublicKeyCredentialRequestOptions,
        event: Event | None = None,
    ) -> AssertionSelection:
        """Get an assertion.

        :param options: PublicKeyCredentialRequestOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """
        raise NotImplementedError()


class UserInteraction:
    """Provides user interaction to the Client.

    Users of Fido2Client should subclass this to implement asking the user to perform
    specific actions, such as entering a PIN or touching their"""

    def prompt_up(self) -> None:
        """Called when the authenticator is awaiting a user presence check."""
        logger.info("User Presence check required.")

    def request_pin(
        self, permissions: ClientPin.PERMISSION, rp_id: str | None
    ) -> str | None:
        """Called when the client requires a PIN from the user.

        Should return a PIN, or None/Empty to cancel."""
        logger.info("PIN requested, but UserInteraction does not support it.")
        return None

    def request_uv(self, permissions: ClientPin.PERMISSION, rp_id: str | None) -> bool:
        """Called when the client is about to request UV from the user.

        Should return True if allowed, or False to cancel."""
        logger.info("User Verification requested.")
        return True


class ClientDataCollector(abc.ABC):
    """Provides client data and logic to the Client.

    Users should subclass this to implement custom behavior for determining the origin,
    validating the RP ID, and providing client data for a request.
    """

    @abc.abstractmethod
    def collect_client_data(
        self,
        options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
    ) -> tuple[CollectedClientData, str]:
        """Called when the client is preparing a request.

        Should return a CollectedClientData object with the client data for the request,
        as well as the RP ID of the credential.
        """


class DefaultClientDataCollector(ClientDataCollector):
    """Default implementation of ClientDataProvider.

    This implementation uses a fixed origin, it can be subclassed to customize specific
    behavior.
    """

    def __init__(
        self,
        origin: str,
        verify: Callable[[str, str], bool] | None = None,
    ):
        self._native = NativeClientDataCollector(origin, verify)
        self._origin = origin

    def get_rp_id(
        self,
        options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
        origin: str,
    ) -> str:
        """Get the RP ID for the given options and origin."""
        if isinstance(options, PublicKeyCredentialCreationOptions):
            rp_id = options.rp.id
        elif isinstance(options, PublicKeyCredentialRequestOptions):
            rp_id = options.rp_id
        else:
            raise ValueError("Invalid options type.")

        try:
            return self._native.get_rp_id(rp_id)
        except ValueError:
            raise ClientError.ERR.BAD_REQUEST("RP ID required for non-https origin.")

    def verify_rp_id(self, rp_id: str, origin: str) -> None:
        """Verify the RP ID for the given origin."""
        try:
            self._native.verify_rp_id_py(rp_id)
        except ValueError:
            raise ClientError.ERR.BAD_REQUEST()

    def get_request_type(self, options) -> str:
        """Get the request type for the given options."""
        if isinstance(options, PublicKeyCredentialCreationOptions):
            return CollectedClientData.TYPE.CREATE
        elif isinstance(options, PublicKeyCredentialRequestOptions):
            return CollectedClientData.TYPE.GET
        else:
            raise ValueError("Invalid options type.")

    def collect_client_data(self, options):
        if isinstance(options, PublicKeyCredentialCreationOptions):
            rp_id = options.rp.id
        elif isinstance(options, PublicKeyCredentialRequestOptions):
            rp_id = options.rp_id
        else:
            raise ValueError("Invalid options type.")

        try:
            cd_bytes, effective_rp_id = self._native.collect_client_data(
                self.get_request_type(options),
                options.challenge,
                rp_id,
            )
        except ValueError:
            raise ClientError.ERR.BAD_REQUEST()

        return CollectedClientData(cd_bytes), effective_rp_id


def _user_keepalive(user_interaction):
    def on_keepalive(status):
        if status == STATUS.UPNEEDED:  # Waiting for touch
            user_interaction.prompt_up()

    return on_keepalive


class Fido2Client(WebAuthnClient):
    """WebAuthn-like client implementation.

    The client allows registration and authentication of WebAuthn credentials against
    an Authenticator using CTAP (1 or 2).

    :param device: CtapDevice to use.
    :param client_data_collector: ClientDataCollector for origin/RP ID handling.
    :param user_interaction: UserInteraction for PIN/UV prompts.
    """

    def __init__(
        self,
        device: CtapDevice,
        client_data_collector: ClientDataCollector,
        user_interaction: UserInteraction = UserInteraction(),
        extensions: Sequence[Any] | None = None,
    ):
        self._client_data_collector = client_data_collector
        on_keepalive = _user_keepalive(user_interaction)

        if extensions is None:
            from ..ctap2.extensions import _DEFAULT_EXTENSIONS

            extensions = _DEFAULT_EXTENSIONS

        self._native = NativeFido2Client(
            device, user_interaction, on_keepalive, list(extensions)
        )
        self._info = Info(**self._native.info)
        self.__enterprise_rpid_list: list[str] | None = None

    @property
    def info(self) -> Info:
        return self._info

    @property
    def _enterprise_rpid_list(self) -> list[str] | None:
        return self.__enterprise_rpid_list

    @_enterprise_rpid_list.setter
    def _enterprise_rpid_list(self, value: list[str] | None) -> None:
        self.__enterprise_rpid_list = value
        self._native.enterprise_rpid_list = value

    def selection(self, event: Event | None = None) -> None:
        self._native.selection(event)

    def make_credential(
        self,
        options: PublicKeyCredentialCreationOptions,
        event: Event | None = None,
    ) -> RegistrationResponse:
        """Creates a credential.

        :param options: PublicKeyCredentialCreationOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        options = PublicKeyCredentialCreationOptions.from_dict(options)
        event = event or Event()
        if options.timeout:
            timer = Timer(options.timeout / 1000, event.set)
            timer.daemon = True
            timer.start()
        else:
            timer = None

        # Gather client data, RP ID from client
        client_data, rp_id = self._client_data_collector.collect_client_data(options)
        logger.debug(f"Register a new credential for RP ID: {rp_id}")

        try:
            att_resp_dict, ext_outputs = self._native.do_make_credential(
                json.dumps(dict(options), cls=_BytesEncoder),
                client_data.hash,
                rp_id,
                event,
            )
        finally:
            if timer:
                timer.cancel()

        att_obj = AttestationObject.create(
            att_resp_dict["fmt"],
            att_resp_dict["auth_data"],
            att_resp_dict["att_stmt"],
        )

        credential = att_obj.auth_data.credential_data
        assert credential is not None  # noqa: S101

        return RegistrationResponse(
            raw_id=credential.credential_id,
            response=AuthenticatorAttestationResponse(
                client_data=client_data, attestation_object=att_obj
            ),
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            client_extension_results=AuthenticationExtensionsClientOutputs(ext_outputs),
            type=PublicKeyCredentialType.PUBLIC_KEY,
        )

    def get_assertion(
        self,
        options: PublicKeyCredentialRequestOptions,
        event: Event | None = None,
    ) -> AssertionSelection:
        """Get an assertion.

        :param options: PublicKeyCredentialRequestOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        options = PublicKeyCredentialRequestOptions.from_dict(options)
        event = event or Event()
        if options.timeout:
            timer = Timer(options.timeout / 1000, event.set)
            timer.daemon = True
            timer.start()
        else:
            timer = None

        # Gather client data, RP ID from client
        client_data, rp_id = self._client_data_collector.collect_client_data(options)
        logger.debug(f"Assert a credential for RP ID: {rp_id}")

        try:
            assertions_dicts, ext_outputs_list = self._native.do_get_assertion(
                json.dumps(dict(options), cls=_BytesEncoder),
                client_data.hash,
                rp_id,
                event,
            )
        finally:
            if timer:
                timer.cancel()

        assertions = [AssertionResponse(**a) for a in assertions_dicts]
        return AssertionSelection(client_data, assertions, ext_outputs_list)
