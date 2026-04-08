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
import logging
from enum import IntEnum, IntFlag, unique
from threading import Event
from typing import Any, Callable, ClassVar, Mapping

from _fido2_native.ctap import NativeClientPin
from _fido2_native.pin import NativePinProtocol

from ..cose import CoseKey
from .base import Ctap2

logger = logging.getLogger(__name__)


class PinProtocol(abc.ABC):
    VERSION: ClassVar[int]

    @abc.abstractmethod
    def encapsulate(self, peer_cose_key: CoseKey) -> tuple[Mapping[int, Any], bytes]:
        """Generates an encapsulation of the public key.
        Returns the message to transmit and the shared secret.
        """

    @abc.abstractmethod
    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """Encrypts data"""

    @abc.abstractmethod
    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """Decrypts encrypted data"""

    @abc.abstractmethod
    def authenticate(self, key: bytes, message: bytes) -> bytes:
        """Computes a MAC of the given message."""

    @abc.abstractmethod
    def validate_token(self, token: bytes) -> bytes:
        """Validates that a token is well-formed.
        Returns the token, or if invalid, raises a ValueError.
        """


class PinProtocolV1(PinProtocol):
    """Implementation of the CTAP2 PIN/UV protocol v1.

    :param ctap: An instance of a CTAP2 object.
    :cvar VERSION: The version number of the PIV/UV protocol.
    :cvar IV: An all-zero IV used for some cryptographic operations.
    """

    VERSION = 1
    IV = b"\x00" * 16

    def __init__(self):
        self._native = NativePinProtocol(self.VERSION)

    def encapsulate(self, peer_cose_key):
        return self._native.encapsulate(peer_cose_key[-2], peer_cose_key[-3])

    def encrypt(self, key, plaintext):
        return self._native.encrypt(key, plaintext)

    def decrypt(self, key, ciphertext):
        return self._native.decrypt(key, ciphertext)

    def authenticate(self, key, message):
        return self._native.authenticate(key, message)

    def validate_token(self, token):
        return self._native.validate_token(token)


class PinProtocolV2(PinProtocolV1):
    """Implementation of the CTAP2 PIN/UV protocol v2.

    :param ctap: An instance of a CTAP2 object.
    :cvar VERSION: The version number of the PIV/UV protocol.
    :cvar IV: An all-zero IV used for some cryptographic operations.
    """

    VERSION = 2


class ClientPin:
    """Implementation of the CTAP2 Client PIN API.

    :param ctap: An instance of a CTAP2 object.
    :param protocol: An optional instance of a PinUvAuthProtocol object. If None is
        provided then the latest protocol supported by both library and Authenticator
        will be used.
    """

    PROTOCOLS = [PinProtocolV2, PinProtocolV1]

    @unique
    class CMD(IntEnum):
        GET_PIN_RETRIES = 0x01
        GET_KEY_AGREEMENT = 0x02
        SET_PIN = 0x03
        CHANGE_PIN = 0x04
        GET_TOKEN_USING_PIN_LEGACY = 0x05
        GET_TOKEN_USING_UV = 0x06
        GET_UV_RETRIES = 0x07
        GET_TOKEN_USING_PIN = 0x09

    @unique
    class RESULT(IntEnum):
        KEY_AGREEMENT = 0x01
        PIN_UV_TOKEN = 0x02
        PIN_RETRIES = 0x03
        POWER_CYCLE_STATE = 0x04
        UV_RETRIES = 0x05

    @unique
    class PERMISSION(IntFlag):
        MAKE_CREDENTIAL = 0x01
        GET_ASSERTION = 0x02
        CREDENTIAL_MGMT = 0x04
        BIO_ENROLL = 0x08
        LARGE_BLOB_WRITE = 0x10
        AUTHENTICATOR_CFG = 0x20
        PERSISTENT_CREDENTIAL_MGMT = 0x40

    @staticmethod
    def is_supported(info):
        """Checks if ClientPin functionality is supported.

        Note that the ClientPin function is still usable without support for client
        PIN functionality, as UV token may still be supported.
        """
        return "clientPin" in info.options

    @staticmethod
    def is_token_supported(info):
        """Checks if pinUvAuthToken is supported."""
        return info.options.get("pinUvAuthToken") is True

    def __init__(self, ctap: Ctap2, protocol: PinProtocol | None = None):
        if protocol is None:
            for proto in ClientPin.PROTOCOLS:
                if proto.VERSION in ctap.info.pin_uv_protocols:
                    self.protocol: PinProtocol = proto()
                    break
            else:
                raise ValueError("No compatible PIN/UV protocols supported!")
        else:
            self.protocol = protocol
        self._native = NativeClientPin(
            ctap._native,
            self.protocol.VERSION,
        )

    def _get_shared_secret(self):
        return self._native.get_shared_secret()

    def get_pin_token(
        self,
        pin: str,
        permissions: ClientPin.PERMISSION | None = None,
        permissions_rpid: str | None = None,
    ) -> bytes:
        """Get a PIN/UV token from the authenticator using PIN.

        :param pin: The PIN of the authenticator.
        :param permissions: The permissions to associate with the token.
        :param permissions_rpid: The permissions RPID to associate with the token.
        :return: A PIN/UV token.
        """
        return self._native.get_pin_token(
            pin,
            int(permissions) if permissions is not None else None,
            permissions_rpid,
        )

    def get_uv_token(
        self,
        permissions: ClientPin.PERMISSION | None = None,
        permissions_rpid: str | None = None,
        event: Event | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> bytes:
        """Get a PIN/UV token from the authenticator using built-in UV.

        :param permissions: The permissions to associate with the token.
        :param permissions_rpid: The permissions RPID to associate with the token.
        :param event: An optional threading.Event which can be used to cancel
            the invocation.
        :param on_keepalive: An optional callback to handle keep-alive messages
            from the authenticator. The function is only called once for
            consecutive keep-alive messages with the same status.
        :return: A PIN/UV token.
        """
        return self._native.get_uv_token(
            int(permissions) if permissions is not None else None,
            permissions_rpid,
            event,
            on_keepalive,
        )

    def get_pin_retries(self) -> tuple[int, int | None]:
        """Get the number of PIN retries remaining.

        :return: A tuple of the number of PIN attempts remaining until the
        authenticator is locked, and the power cycle state, if available.
        """
        return self._native.get_pin_retries()

    def get_uv_retries(self) -> int:
        """Get the number of UV retries remaining.

        :return: A tuple of the number of UV attempts remaining until the
        authenticator is locked, and the power cycle state, if available.
        """
        return self._native.get_uv_retries()

    def set_pin(self, pin: str) -> None:
        """Set the PIN of the autenticator.

        This only works when no PIN is set. To change the PIN when set, use
        change_pin.

        :param pin: A PIN to set.
        """
        self._native.set_pin(pin)

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        """Change the PIN of the authenticator.

        This only works when a PIN is already set. If no PIN is set, use
        set_pin.

        :param old_pin: The currently set PIN.
        :param new_pin: The new PIN to set.
        """
        self._native.change_pin(old_pin, new_pin)
