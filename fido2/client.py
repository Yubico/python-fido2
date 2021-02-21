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

from __future__ import absolute_import, unicode_literals, division

from .hid import STATUS
from .ctap import CtapError
from .ctap1 import Ctap1, APDU, ApduError
from .ctap2 import (
    Ctap2,
    AttestationObject,
    AssertionResponse,
    Info,
    ClientPin,
)
from .ctap2.extensions import Ctap2Extension
from .webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
)
from .cose import ES256
from .rpid import verify_rp_id, verify_app_id
from .utils import sha256, websafe_decode, websafe_encode
from enum import Enum, IntEnum, unique
from threading import Timer, Event

import json
import six
import platform


class ClientData(bytes):
    def __init__(self, _):
        super(ClientData, self).__init__()
        self.data = json.loads(self.decode())

    def get(self, key):
        return self.data[key]

    @property
    def challenge(self):
        return websafe_decode(self.get("challenge"))

    @property
    def b64(self):
        return websafe_encode(self)

    @property
    def hash(self):
        return sha256(self)

    @classmethod
    def build(cls, **kwargs):
        return cls(json.dumps(kwargs).encode())

    @classmethod
    def from_b64(cls, data):
        return cls(websafe_decode(data))

    def __repr__(self):
        return self.decode()

    def __str__(self):
        return self.decode()


class ClientError(Exception):
    @unique
    class ERR(IntEnum):
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
            r += " (cause: {})".format(self.cause)
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
    def __init__(
        self, code=ClientError.ERR.BAD_REQUEST, cause="Pin required but not provided"
    ):
        super(PinRequiredError, self).__init__(code, cause)


def _call_polling(poll_delay, event, on_keepalive, func, *args, **kwargs):
    event = event or Event()
    while not event.is_set():
        try:
            return func(*args, **kwargs)
        except ApduError as e:
            if e.code == APDU.USE_NOT_SATISFIED:
                if on_keepalive:
                    on_keepalive(STATUS.UPNEEDED)
                    on_keepalive = None
                event.wait(poll_delay)
            else:
                raise ClientError.ERR.OTHER_ERROR(e)
        except CtapError as e:
            raise _ctap2client_err(e)
    raise ClientError.ERR.TIMEOUT()


@unique
class U2F_TYPE(six.text_type, Enum):
    REGISTER = "navigator.id.finishEnrollment"
    SIGN = "navigator.id.getAssertion"


class U2fClient(object):
    """U2F-like client implementation.

    The client allows registration and authentication of U2F credentials against
    an Authenticator using CTAP 1. Prefer using Fido2Client if possible.

    :param device: CtapDevice to use.
    :param str origin: The origin to use.
    :param verify: Function to verify an APP ID for a given origin.
    """

    def __init__(self, device, origin, verify=verify_app_id):
        self.poll_delay = 0.25
        self.ctap = Ctap1(device)
        self.origin = origin
        self._verify = verify

    def _verify_app_id(self, app_id):
        try:
            if self._verify(app_id, self.origin):
                return
        except Exception:  # nosec
            pass  # Fall through to ClientError
        raise ClientError.ERR.BAD_REQUEST()

    def register(
        self, app_id, register_requests, registered_keys, event=None, on_keepalive=None
    ):
        self._verify_app_id(app_id)

        version = self.ctap.get_version()
        dummy_param = b"\0" * 32
        for key in registered_keys:
            if key["version"] != version:
                continue
            key_app_id = key.get("appId", app_id)
            app_param = sha256(key_app_id.encode())
            self._verify_app_id(key_app_id)
            key_handle = websafe_decode(key["keyHandle"])
            try:
                self.ctap.authenticate(dummy_param, app_param, key_handle, True)
                raise ClientError.ERR.DEVICE_INELIGIBLE()  # Bad response
            except ApduError as e:
                if e.code == APDU.USE_NOT_SATISFIED:
                    raise ClientError.ERR.DEVICE_INELIGIBLE()
            except CtapError as e:
                raise _ctap2client_err(e)

        for request in register_requests:
            if request["version"] == version:
                challenge = request["challenge"]
                break
        else:
            raise ClientError.ERR.DEVICE_INELIGIBLE()

        client_data = ClientData.build(
            typ=U2F_TYPE.REGISTER, challenge=challenge, origin=self.origin
        )
        app_param = sha256(app_id.encode())

        reg_data = _call_polling(
            self.poll_delay,
            event,
            on_keepalive,
            self.ctap.register,
            client_data.hash,
            app_param,
        )

        return {"registrationData": reg_data.b64, "clientData": client_data.b64}

    def sign(self, app_id, challenge, registered_keys, event=None, on_keepalive=None):
        client_data = ClientData.build(
            typ=U2F_TYPE.SIGN, challenge=challenge, origin=self.origin
        )

        version = self.ctap.get_version()
        for key in registered_keys:
            if key["version"] == version:
                key_app_id = key.get("appId", app_id)
                self._verify_app_id(key_app_id)
                key_handle = websafe_decode(key["keyHandle"])
                app_param = sha256(key_app_id.encode())
                try:
                    signature_data = _call_polling(
                        self.poll_delay,
                        event,
                        on_keepalive,
                        self.ctap.authenticate,
                        client_data.hash,
                        app_param,
                        key_handle,
                    )
                    break
                except ClientError:  # nosec
                    pass  # Ignore and try next key
        else:
            raise ClientError.ERR.DEVICE_INELIGIBLE()

        return {
            "clientData": client_data.b64,
            "signatureData": signature_data.b64,
            "keyHandle": key["keyHandle"],
        }


@unique
class WEBAUTHN_TYPE(six.text_type, Enum):
    MAKE_CREDENTIAL = "webauthn.create"
    GET_ASSERTION = "webauthn.get"


class _BaseClient(object):
    def __init__(self, origin, verify):
        self.origin = origin
        self._verify = verify

    def _verify_rp_id(self, rp_id):
        try:
            if self._verify(rp_id, self.origin):
                return
        except Exception:  # nosec
            pass  # Fall through to ClientError
        raise ClientError.ERR.BAD_REQUEST()

    def _build_client_data(self, typ, challenge, extensions={}):
        return ClientData.build(
            type=typ,
            origin=self.origin,
            challenge=websafe_encode(challenge),
            clientExtensions=extensions,
        )


class AssertionSelection(object):
    """GetAssertion result holding one or more assertions.

    Since multiple assertions may be retured by Fido2Client.get_assertion, this result
    is returned which can be used to select a specific response to get.
    """

    def __init__(self, client_data, assertions):
        self._client_data = client_data
        self._assertions = assertions

    def get_assertions(self):
        """Get the raw AssertionResponses available to inspect before selecting one."""
        return self._assertions

    def _get_extension_results(self, assertion):
        return {}

    def get_response(self, index):
        """Get a single response."""
        assertion = self._assertions[index]

        return AuthenticatorAssertionResponse(
            self._client_data,
            assertion.auth_data,
            assertion.signature,
            assertion.user["id"] if assertion.user else None,
            assertion.credential["id"] if assertion.credential else None,
            self._get_extension_results(assertion),
        )


class Fido2ClientAssertionSelection(AssertionSelection):
    def __init__(self, client_data, assertions, extensions):
        super(Fido2ClientAssertionSelection, self).__init__(client_data, assertions)
        self._extensions = extensions

    def _get_extension_results(self, assertion):
        # Process extenstion outputs
        extension_outputs = {}
        try:
            for ext in self._extensions:
                output = ext.process_get_output(assertion.auth_data)
                if output is not None:
                    extension_outputs.update(output)
        except ValueError as e:
            raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(e)
        return extension_outputs


def _default_extensions():
    return [cls for cls in Ctap2Extension.__subclasses__() if hasattr(cls, "NAME")]


_CTAP1_INFO = Info.create(["U2F_V2"])


class Fido2Client(_BaseClient):
    """WebAuthn-like client implementation.

    The client allows registration and authentication of WebAuthn credentials against
    an Authenticator using CTAP (1 or 2).

    :param device: CtapDevice to use.
    :param str origin: The origin to use.
    :param verify: Function to verify an RP ID for a given origin.
    """

    def __init__(self, device, origin, verify=verify_rp_id, extension_types=None):
        super(Fido2Client, self).__init__(origin, verify)

        self.extensions = extension_types or _default_extensions()
        self.ctap1_poll_delay = 0.25
        try:
            self.ctap2 = Ctap2(device)
            self.info = self.ctap2.info
            try:
                self.client_pin = ClientPin(self.ctap2)
            except ValueError:
                self.client_pin = None
            self._do_make_credential = self._ctap2_make_credential
            self._do_get_assertion = self._ctap2_get_assertion
        except (ValueError, CtapError):
            self.ctap1 = Ctap1(device)
            self.info = _CTAP1_INFO
            self._do_make_credential = self._ctap1_make_credential
            self._do_get_assertion = self._ctap1_get_assertion

    def _should_use_uv(self, user_verification, mc):
        uv_supported = any(
            k in self.info.options for k in ("uv", "clientPin", "bioEnroll")
        )
        uv_configured = any(
            self.info.options.get(k) for k in ("uv", "clientPin", "bioEnroll")
        )

        if (
            user_verification == UserVerificationRequirement.REQUIRED
            or (
                user_verification == UserVerificationRequirement.PREFERRED
                and uv_supported
            )
            or self.info.options.get("alwaysUv")
        ):
            if not uv_configured:
                raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(
                    "User verification not configured/supported"
                )
            return True
        elif mc and uv_configured and not self.info.options.get("makeCredUvNotRqd"):
            return True
        return False

    def _get_token(self, permissions, rp_id, pin, event, on_keepalive):
        if pin:
            if self.info.options.get("clientPin"):
                return self.client_pin.get_pin_token(pin, permissions, rp_id)
            else:
                raise ClientError.ERR.BAD_REQUEST("PIN provided, but not set/supported")
        elif self.info.options.get("uv"):
            if self.info.options.get("pinUvAuthToken") and self.info.options.get(
                "bioEnroll"
            ):
                try:
                    return self.client_pin.get_uv_token(
                        permissions, rp_id, event, on_keepalive
                    )
                except CtapError as e:
                    raise _ctap2client_err(e, PinRequiredError)
            else:
                return None  # No token, use uv=True
        elif self.info.options.get("clientPin"):
            raise PinRequiredError()
        raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(
            "User verification not configured/supported"
        )

    def _get_auth_params(
        self, client_data, rp_id, user_verification, pin, event, on_keepalive
    ):
        mc = client_data.get("type") == WEBAUTHN_TYPE.MAKE_CREDENTIAL
        self.info = self.ctap2.get_info()  # Make sure we have "fresh" info

        pin_auth = None
        pin_protocol = None
        internal_uv = False
        if self._should_use_uv(user_verification, mc):
            permission = (
                ClientPin.PERMISSION.MAKE_CREDENTIAL
                if mc
                else ClientPin.PERMISSION.GET_ASSERTION
            )
            token = self._get_token(permission, rp_id, pin, event, on_keepalive)
            if token:
                pin_protocol = self.client_pin.protocol.VERSION
                pin_auth = self.client_pin.protocol.authenticate(
                    token, client_data.hash
                )
            else:
                internal_uv = True
        return pin_protocol, pin_auth, internal_uv

    def make_credential(self, options, **kwargs):
        """Creates a credential.

        :param options: PublicKeyCredentialCreationOptions data.
        :param pin: (optional) Used if PIN verification is required.
        :param threading.Event event: (optional) Signal to abort the operation.
        :param on_keepalive: (optional) function to call with CTAP status updates.
        """

        options = PublicKeyCredentialCreationOptions._wrap(options)
        pin = kwargs.get("pin")
        event = kwargs.get("event", Event())
        if options.timeout:
            timer = Timer(options.timeout / 1000, event.set)
            timer.daemon = True
            timer.start()

        self._verify_rp_id(options.rp.id)

        client_data = self._build_client_data(
            WEBAUTHN_TYPE.MAKE_CREDENTIAL, options.challenge
        )

        selection = options.authenticator_selection or AuthenticatorSelectionCriteria()

        try:
            att_obj, extension_outputs = self._do_make_credential(
                client_data,
                options.rp,
                options.user,
                options.pub_key_cred_params,
                options.exclude_credentials,
                options.extensions,
                selection.require_resident_key,
                selection.user_verification,
                pin,
                event,
                kwargs.get("on_keepalive"),
            )
            return AuthenticatorAttestationResponse(
                client_data, att_obj, extension_outputs,
            )
        except CtapError as e:
            raise _ctap2client_err(e)
        finally:
            if options.timeout:
                timer.cancel()

    def _ctap2_make_credential(
        self,
        client_data,
        rp,
        user,
        key_params,
        exclude_list,
        extensions,
        rk,
        user_verification,
        pin,
        event,
        on_keepalive,
    ):
        if exclude_list:
            # Filter out credential IDs which are too long
            max_len = self.info.max_cred_id_length
            if max_len:
                exclude_list = [e for e in exclude_list if len(e) <= max_len]

            # Reject the request if too many credentials remain.
            max_creds = self.info.max_creds_in_list
            if max_creds and len(exclude_list) > max_creds:
                raise ClientError.ERR.BAD_REQUEST("exclude_list too long")

        # Process extensions
        client_inputs = extensions or {}
        extension_inputs = {}
        used_extensions = []
        try:
            for ext in [cls(self.ctap2) for cls in self.extensions]:
                auth_input = ext.process_create_input(client_inputs)
                if auth_input is not None:
                    used_extensions.append(ext)
                    extension_inputs[ext.NAME] = auth_input
        except ValueError as e:
            raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(e)

        # Handle auth
        pin_protocol, pin_auth, internal_uv = self._get_auth_params(
            client_data, rp["id"], user_verification, pin, event, on_keepalive
        )

        if not (rk or internal_uv):
            options = None
        else:
            options = {}
            if rk:
                options["rk"] = True
            if internal_uv:
                options["uv"] = True

        att_obj = self.ctap2.make_credential(
            client_data.hash,
            rp,
            user,
            key_params,
            exclude_list or None,
            extension_inputs or None,
            options,
            pin_auth,
            pin_protocol,
            event,
            on_keepalive,
        )

        # Process extenstion outputs
        extension_outputs = {}
        try:
            for ext in used_extensions:
                output = ext.process_create_output(att_obj.auth_data)
                if output is not None:
                    extension_outputs.update(output)
        except ValueError as e:
            raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(e)

        return att_obj, extension_outputs

    def _ctap1_make_credential(
        self,
        client_data,
        rp,
        user,
        key_params,
        exclude_list,
        extensions,
        rk,
        user_verification,
        pin,
        event,
        on_keepalive,
    ):
        if (
            rk
            or user_verification == UserVerificationRequirement.REQUIRED
            or ES256.ALGORITHM not in [p.alg for p in key_params]
        ):
            raise CtapError(CtapError.ERR.UNSUPPORTED_OPTION)

        app_param = sha256(rp["id"].encode())

        dummy_param = b"\0" * 32
        for cred in exclude_list or []:
            key_handle = cred["id"]
            try:
                self.ctap1.authenticate(dummy_param, app_param, key_handle, True)
                raise ClientError.ERR.OTHER_ERROR()  # Shouldn't happen
            except ApduError as e:
                if e.code == APDU.USE_NOT_SATISFIED:
                    _call_polling(
                        self.ctap1_poll_delay,
                        event,
                        on_keepalive,
                        self.ctap1.register,
                        dummy_param,
                        dummy_param,
                    )
                    raise ClientError.ERR.DEVICE_INELIGIBLE()

        return (
            AttestationObject.from_ctap1(
                app_param,
                _call_polling(
                    self.ctap1_poll_delay,
                    event,
                    on_keepalive,
                    self.ctap1.register,
                    client_data.hash,
                    app_param,
                ),
            ),
            {},
        )

    def get_assertion(self, options, **kwargs):
        """Get an assertion.

        :param options: PublicKeyCredentialRequestOptions data.
        :param pin: (optional) Used if PIN verification is required.
        :param threading.Event event: (optional) Signal to abort the operation.
        :param on_keepalive: (optional) Not implemented.
        """

        options = PublicKeyCredentialRequestOptions._wrap(options)
        pin = kwargs.get("pin")
        event = kwargs.get("event", Event())
        if options.timeout:
            timer = Timer(options.timeout / 1000, event.set)
            timer.daemon = True
            timer.start()

        self._verify_rp_id(options.rp_id)

        client_data = self._build_client_data(
            WEBAUTHN_TYPE.GET_ASSERTION, options.challenge
        )

        try:
            assertions, used_extensions = self._do_get_assertion(
                client_data,
                options.rp_id,
                options.allow_credentials,
                options.extensions,
                options.user_verification,
                pin,
                event,
                kwargs.get("on_keepalive"),
            )
            return Fido2ClientAssertionSelection(
                client_data, assertions, used_extensions,
            )
        except CtapError as e:
            raise _ctap2client_err(e)
        finally:
            if options.timeout:
                timer.cancel()

    def _ctap2_get_assertion(
        self,
        client_data,
        rp_id,
        allow_list,
        extensions,
        user_verification,
        pin,
        event,
        on_keepalive,
    ):
        pin_protocol, pin_auth, internal_uv = self._get_auth_params(
            client_data, rp_id, user_verification, pin, event, on_keepalive
        )
        if internal_uv:
            options = {"uv": True}
        else:
            options = None

        if allow_list:
            # Filter out credential IDs which are too long
            max_len = self.info.max_cred_id_length
            if max_len:
                allow_list = [e for e in allow_list if len(e) <= max_len]
            if not allow_list:
                raise CtapError(CtapError.ERR.NO_CREDENTIALS)

            # Reject the request if too many credentials remain.
            max_creds = self.info.max_creds_in_list
            if max_creds and len(allow_list) > max_creds:
                raise ClientError.ERR.BAD_REQUEST("allow_list too long")

        # Process extensions
        client_inputs = extensions or {}
        extension_inputs = {}
        used_extensions = []
        try:
            for ext in [cls(self.ctap2) for cls in self.extensions]:
                auth_input = ext.process_get_input(client_inputs)
                if auth_input is not None:
                    used_extensions.append(ext)
                    extension_inputs[ext.NAME] = auth_input
        except ValueError as e:
            raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(e)

        assertions = self.ctap2.get_assertions(
            rp_id,
            client_data.hash,
            allow_list or None,
            extension_inputs or None,
            options,
            pin_auth,
            pin_protocol,
            event,
            on_keepalive,
        )

        return assertions, used_extensions

    def _ctap1_get_assertion(
        self,
        client_data,
        rp_id,
        allow_list,
        extensions,
        user_verification,
        pin,
        event,
        on_keepalive,
    ):
        if user_verification == UserVerificationRequirement.REQUIRED or not allow_list:
            raise CtapError(CtapError.ERR.UNSUPPORTED_OPTION)

        app_param = sha256(rp_id.encode())
        client_param = client_data.hash
        for cred in allow_list:
            try:
                auth_resp = _call_polling(
                    self.ctap1_poll_delay,
                    event,
                    on_keepalive,
                    self.ctap1.authenticate,
                    client_param,
                    app_param,
                    cred["id"],
                )
                assertions = [AssertionResponse.from_ctap1(app_param, cred, auth_resp)]
                return assertions, []
            except ClientError as e:
                if e.code == ClientError.ERR.TIMEOUT:
                    raise  # Other errors are ignored so we move to the next.
        raise ClientError.ERR.DEVICE_INELIGIBLE()


_WIN_INFO = Info.create(["U2F_V2", "FIDO_2_0"])

if platform.system().lower() == "windows":
    try:
        from .win_api import (
            WinAPI,
            WebAuthNAuthenticatorAttachment,
            WebAuthNUserVerificationRequirement,
            WebAuthNAttestationConvoyancePreference,
        )
    except Exception:  # nosec # TODO: Make this less generic
        pass


class WindowsClient(_BaseClient):
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

    def __init__(self, origin, verify=verify_rp_id, handle=None):
        super(WindowsClient, self).__init__(origin, verify)
        self.api = WinAPI(handle)

    @property
    def info(self):
        return _WIN_INFO

    @staticmethod
    def is_available():
        return platform.system().lower() == "windows" and WinAPI.version > 0

    def make_credential(self, options, **kwargs):
        """Create a credential using Windows WebAuthN APIs.

        :param options: PublicKeyCredentialCreationOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        options = PublicKeyCredentialCreationOptions._wrap(options)

        self._verify_rp_id(options.rp.id)

        client_data = self._build_client_data(
            WEBAUTHN_TYPE.MAKE_CREDENTIAL, options.challenge
        )

        selection = options.authenticator_selection or AuthenticatorSelectionCriteria()

        try:
            result = self.api.make_credential(
                options.rp,
                options.user,
                options.pub_key_cred_params,
                client_data,
                options.timeout or 0,
                selection.require_resident_key or False,
                WebAuthNAuthenticatorAttachment.from_string(
                    selection.authenticator_attachment or "any"
                ),
                WebAuthNUserVerificationRequirement.from_string(
                    selection.user_verification or "discouraged"
                ),
                WebAuthNAttestationConvoyancePreference.from_string(
                    options.attestation or "none"
                ),
                options.exclude_credentials,
                options.extensions,
                kwargs.get("event"),
            )
        except OSError as e:
            raise ClientError.ERR.OTHER_ERROR(e)

        return AuthenticatorAttestationResponse(
            client_data, AttestationObject(result), {}
        )

    def get_assertion(self, options, **kwargs):
        """Get assertion using Windows WebAuthN APIs.

        :param options: PublicKeyCredentialRequestOptions data.
        :param threading.Event event: (optional) Signal to abort the operation.
        """

        options = PublicKeyCredentialRequestOptions._wrap(options)

        self._verify_rp_id(options.rp_id)

        client_data = self._build_client_data(
            WEBAUTHN_TYPE.GET_ASSERTION, options.challenge
        )

        try:
            (credential, auth_data, signature, user_id) = self.api.get_assertion(
                options.rp_id,
                client_data,
                options.timeout or 0,
                WebAuthNAuthenticatorAttachment.ANY,
                WebAuthNUserVerificationRequirement.from_string(
                    options.user_verification or "discouraged"
                ),
                options.allow_credentials,
                options.extensions,
                kwargs.get("event"),
            )
        except OSError as e:
            raise ClientError.ERR.OTHER_ERROR(e)

        user = {"id": user_id} if user_id else None
        return AssertionSelection(
            client_data,
            [AssertionResponse.create(credential, auth_data, signature, user)],
        )
