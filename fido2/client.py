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

from __future__ import absolute_import, unicode_literals

from .hid import STATUS
from .ctap import CtapError
from .ctap1 import CTAP1, APDU, ApduError
from .ctap2 import (CTAP2, PinProtocolV1, AttestationObject, AssertionResponse)
from .cose import ES256
from .rpid import verify_rp_id, verify_app_id
from .utils import Timeout, sha256, hmac_sha256, websafe_decode, websafe_encode
from enum import Enum, IntEnum, unique
import json
import six


class ClientData(bytes):
    def __init__(self, _):
        super(ClientData, self).__init__()
        self.data = json.loads(self.decode())

    def get(self, key):
        return self.data[key]

    @property
    def challenge(self):
        return websafe_decode(self.get('challenge'))

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
        r = 'Client error: {0} - {0.name}'.format(self.code)
        if self.cause:
            r += '. Caused by {}'.format(self.cause)
        return r


def _ctap2client_err(e):
    if e.code in [CtapError.ERR.CREDENTIAL_EXCLUDED,
                  CtapError.ERR.NO_CREDENTIALS]:
        ce = ClientError.ERR.DEVICE_INELIGIBLE
    elif e.code in [CtapError.ERR.KEEPALIVE_CANCEL,
                    CtapError.ERR.ACTION_TIMEOUT,
                    CtapError.ERR.USER_ACTION_TIMEOUT]:
        ce = ClientError.ERR.TIMEOUT
    elif e.code in [CtapError.ERR.UNSUPPORTED_ALGORITHM,
                    CtapError.ERR.UNSUPPORTED_OPTION,
                    CtapError.ERR.UNSUPPORTED_EXTENSION,
                    CtapError.ERR.KEY_STORE_FULL]:
        ce = ClientError.ERR.CONFIGURATION_UNSUPPORTED
    elif e.code in [CtapError.ERR.INVALID_COMMAND,
                    CtapError.ERR.CBOR_UNEXPECTED_TYPE,
                    CtapError.ERR.INVALID_CBOR,
                    CtapError.ERR.MISSING_PARAMETER,
                    CtapError.ERR.INVALID_OPTION,
                    CtapError.ERR.PIN_REQUIRED,
                    CtapError.ERR.PIN_INVALID,
                    CtapError.ERR.PIN_BLOCKED,
                    CtapError.ERR.PIN_NOT_SET,
                    CtapError.ERR.PIN_POLICY_VIOLATION,
                    CtapError.ERR.PIN_TOKEN_EXPIRED,
                    CtapError.ERR.PIN_AUTH_INVALID,
                    CtapError.ERR.PIN_AUTH_BLOCKED,
                    CtapError.ERR.REQUEST_TOO_LARGE,
                    CtapError.ERR.OPERATION_DENIED]:
        ce = ClientError.ERR.BAD_REQUEST
    else:
        ce = ClientError.ERR.OTHER_ERROR

    return ce(e)


def _call_polling(poll_delay, timeout, on_keepalive, func, *args, **kwargs):
    with Timeout(timeout or 30) as event:
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
    REGISTER = 'navigator.id.finishEnrollment'
    SIGN = 'navigator.id.getAssertion'


class U2fClient(object):
    def __init__(self, device, origin, verify=verify_app_id):
        self.poll_delay = 0.25
        self.ctap = CTAP1(device)
        self.origin = origin
        self._verify = verify

    def _verify_app_id(self, app_id):
        try:
            if self._verify(app_id, self.origin):
                return
        except Exception:
            pass  # Fall through to ClientError
        raise ClientError.ERR.BAD_REQUEST()

    def register(self, app_id, register_requests, registered_keys, timeout=None,
                 on_keepalive=None):
        self._verify_app_id(app_id)

        version = self.ctap.get_version()
        dummy_param = b'\0' * 32
        for key in registered_keys:
            if key['version'] != version:
                continue
            key_app_id = key.get('appId', app_id)
            app_param = sha256(key_app_id.encode())
            self._verify_app_id(key_app_id)
            key_handle = websafe_decode(key['keyHandle'])
            try:
                self.ctap.authenticate(dummy_param, app_param, key_handle, True)
                raise ClientError.ERR.DEVICE_INELIGIBLE()  # Bad response
            except ApduError as e:
                if e.code == APDU.USE_NOT_SATISFIED:
                    raise ClientError.ERR.DEVICE_INELIGIBLE()
            except CtapError as e:
                raise _ctap2client_err(e)

        for request in register_requests:
            if request['version'] == version:
                challenge = request['challenge']
                break
        else:
            raise ClientError.ERR.DEVICE_INELIGIBLE()

        client_data = ClientData.build(
            typ=U2F_TYPE.REGISTER,
            challenge=challenge,
            origin=self.origin
        )
        app_param = sha256(app_id.encode())

        reg_data = _call_polling(
            self.poll_delay, timeout, on_keepalive, self.ctap.register,
            client_data.hash, app_param
        )

        return {
            'registrationData': reg_data.b64,
            'clientData': client_data.b64
        }

    def sign(self, app_id, challenge, registered_keys, timeout=None,
             on_keepalive=None):
        client_data = ClientData.build(
            typ=U2F_TYPE.SIGN,
            challenge=challenge,
            origin=self.origin
        )

        version = self.ctap.get_version()
        for key in registered_keys:
            if key['version'] == version:
                key_app_id = key.get('appId', app_id)
                self._verify_app_id(key_app_id)
                key_handle = websafe_decode(key['keyHandle'])
                app_param = sha256(key_app_id.encode())
                try:
                    signature_data = _call_polling(
                        self.poll_delay, timeout, on_keepalive,
                        self.ctap.authenticate, client_data.hash, app_param,
                        key_handle
                    )
                    break
                except ClientError:
                    pass  # Ignore and try next key
        else:
            raise ClientError.ERR.DEVICE_INELIGIBLE()

        return {
            'clientData': client_data.b64,
            'signatureData': signature_data.b64,
            'keyHandle': key['keyHandle']
        }


@unique
class FIDO2_TYPE(six.text_type, Enum):
    MAKE_CREDENTIAL = 'webauthn.create'
    GET_ASSERTION = 'webauthn.get'


class Fido2Client(object):
    def __init__(self, device, origin, verify=verify_rp_id):
        self.ctap1_poll_delay = 0.25
        self.origin = origin
        self._verify = verify
        try:
            self.ctap2 = CTAP2(device)
            self.pin_protocol = PinProtocolV1(self.ctap2)
            self._do_make_credential = self._ctap2_make_credential
            self._do_get_assertion = self._ctap2_get_assertion
        except ValueError:
            self.ctap1 = CTAP1(device)
            self._do_make_credential = self._ctap1_make_credential
            self._do_get_assertion = self._ctap1_get_assertion

    def _verify_rp_id(self, rp_id):
        try:
            if self._verify(rp_id, self.origin):
                return
        except Exception:
            pass  # Fall through to ClientError
        raise ClientError.ERR.BAD_REQUEST()

    def make_credential(self, rp, user, challenge, algos=[ES256.ALGORITHM],
                        exclude_list=None, extensions=None, rk=False, uv=False,
                        pin=None, timeout=None, on_keepalive=None):

        self._verify_rp_id(rp['id'])

        client_data = ClientData.build(
            type=FIDO2_TYPE.MAKE_CREDENTIAL,
            clientExtensions={},
            challenge=challenge,
            origin=self.origin
        )

        try:
            return self._do_make_credential(
                client_data, rp, user, algos, exclude_list, extensions, rk, uv,
                pin, timeout, on_keepalive
            ), client_data
        except CtapError as e:
            raise _ctap2client_err(e)

    def _ctap2_make_credential(self, client_data, rp, user, algos, exclude_list,
                               extensions, rk, uv, pin, timeout, on_keepalive):
        key_params = [{'type': 'public-key', 'alg': alg} for alg in algos]

        info = self.ctap2.get_info()
        pin_auth = None
        pin_protocol = None
        if pin:
            pin_protocol = self.pin_protocol.VERSION
            if pin_protocol not in info.pin_protocols:
                raise ValueError('Device does not support PIN protocol: %d!' %
                                 pin_protocol)
            pin_token = self.pin_protocol.get_pin_token(pin)
            pin_auth = hmac_sha256(pin_token, client_data.hash)[:16]
        elif info.options.get('clientPin'):
            raise ValueError('PIN required!')

        if not (rk or uv):
            options = None
        else:
            options = {}
            if rk:
                options['rk'] = True
            if uv:
                options['uv'] = True

        return self.ctap2.make_credential(client_data.hash, rp, user,
                                          key_params, exclude_list,
                                          extensions, options, pin_auth,
                                          pin_protocol, timeout, on_keepalive)

    def _ctap1_make_credential(self, client_data, rp, user, algos, exclude_list,
                               extensions, rk, uv, pin, timeout, on_keepalive):
        if rk or uv or ES256.ALGORITHM not in algos:
            raise CtapError(CtapError.ERR.UNSUPPORTED_OPTION)

        app_param = sha256(rp['id'].encode())

        dummy_param = b'\0' * 32
        for cred in exclude_list or []:
            key_handle = cred['id']
            try:
                self.ctap1.authenticate(
                    dummy_param, app_param, key_handle, True)
                raise ClientError.ERR.OTHER_ERROR()  # Shouldn't happen
            except ApduError as e:
                if e.code == APDU.USE_NOT_SATISFIED:
                    _call_polling(self.ctap1_poll_delay, timeout, on_keepalive,
                                  self.ctap1.register, dummy_param, dummy_param)
                    raise ClientError.ERR.DEVICE_INELIGIBLE()

        return AttestationObject.from_ctap1(
            app_param,
            _call_polling(self.ctap1_poll_delay, timeout, on_keepalive,
                          self.ctap1.register, client_data.hash, app_param)
        )

    def get_assertion(self, rp_id, challenge, allow_list=None, extensions=None,
                      up=True, uv=False, pin=None, timeout=None,
                      on_keepalive=None):

        self._verify_rp_id(rp_id)

        client_data = ClientData.build(
            type=FIDO2_TYPE.GET_ASSERTION,
            clientExtensions={},
            challenge=challenge,
            origin=self.origin
        )

        try:
            return self._do_get_assertion(
                client_data, rp_id, allow_list, extensions, up, uv, pin,
                timeout, on_keepalive
            ), client_data
        except CtapError as e:
            raise _ctap2client_err(e)

    def _ctap2_get_assertion(self, client_data, rp_id, allow_list, extensions,
                             up, uv, pin, timeout, on_keepalive):
        info = self.ctap2.get_info()
        pin_auth = None
        pin_protocol = None
        if pin:
            pin_protocol = self.pin_protocol.VERSION
            if pin_protocol not in info.pin_protocols:
                raise ValueError('Device does not support PIN protocol %d!' %
                                 pin_protocol)
            pin_token = self.pin_protocol.get_pin_token(pin)
            pin_auth = hmac_sha256(pin_token, client_data.hash)[:16]
        elif info.options.get('clientPin'):
            raise ValueError('PIN required!')

        options = {}
        if not up:
            options['up'] = False
        if uv:
            options['uv'] = True
        if len(options) == 0:
            options = None

        assertions = [self.ctap2.get_assertion(
            rp_id, client_data.hash, allow_list, extensions, options, pin_auth,
            pin_protocol, timeout, on_keepalive
        )]
        for _ in range((assertions[0].number_of_credentials or 1) - 1):
            assertions.append(self.ctap2.get_next_assertion())
        return assertions

    def _ctap1_get_assertion(self, client_data, rp_id, allow_list, extensions,
                             up, uv, pin, timeout, on_keepalive):
        if (not up) or uv or not allow_list:
            raise CtapError(CtapError.ERR.UNSUPPORTED_OPTION)

        app_param = sha256(rp_id.encode())
        client_param = client_data.hash
        for cred in allow_list:
            try:
                auth_resp = _call_polling(
                    self.ctap1_poll_delay, timeout, on_keepalive,
                    self.ctap1.authenticate, client_param, app_param, cred['id']
                )
                return [
                    AssertionResponse.from_ctap1(app_param, cred, auth_resp)
                ]
            except ClientError as e:
                if e.code == ClientError.ERR.TIMEOUT:
                    raise  # Other errors are ignored so we move to the next.
        raise ClientError.ERR.DEVICE_INELIGIBLE()
