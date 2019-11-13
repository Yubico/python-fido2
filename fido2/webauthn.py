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

from .utils import sha256
from enum import Enum, unique
import six
import re


@unique
class AttestationConveyancePreference(six.text_type, Enum):
    NONE = "none"
    INDIRECT = "indirect"
    DIRECT = "direct"


@unique
class UserVerificationRequirement(six.text_type, Enum):
    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


@unique
class AuthenticatorAttachment(six.text_type, Enum):
    PLATFORM = "platform"
    CROSS_PLATFORM = "cross-platform"


@unique
class AuthenticatorTransport(six.text_type, Enum):
    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    INTERNAL = "internal"


def _snake2camel(name):
    parts = name.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def _camel2snake(name):
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


class DataObjectMeta(type):
    """Metaclass for DataObject, allowing constructors to alternatively be called with
    a dict of values."""

    def __init__(cls, name, bases, dct):
        init = cls.__init__

        def new_init(self, *args, **kwargs):
            if not kwargs and len(args) == 1:
                data = args[0]
                if isinstance(data, dict):
                    args, kwargs = (), {_camel2snake(k): v for k, v in data.items()}
            init(self, *args, **kwargs)

        cls.__init__ = new_init


class DataObject(six.with_metaclass(DataObjectMeta, dict)):
    """Base class for WebAuthn data types, acting both as dict and providing attribute
    access to values.
    """

    def __init__(self, **data):
        keys = {k: _snake2camel(k) for k in data.keys()}
        super(DataObject, self).__init__(
            {keys[k]: v for k, v in data.items() if v is not None}
        )
        super(DataObject, self).__setattr__("_keys", keys)

    def __getattr__(self, name):
        if name in self._keys:
            return self.get(self._keys[name])
        raise AttributeError(
            "'{}' object has no attribute '{}'".format(type(self).__name__, name)
        )

    def __setattr__(self, name, value):
        if name in self._keys:
            self[self._keys[name]] = value
        else:
            super(DataObject, self).__setattr__(name, value)

    def __repr__(self):
        return "{}({!r})".format(self.__class__.__name__, dict(self))


class PublicKeyCredentialRpEntity(DataObject):
    def __init__(self, id, name, icon=None):
        super(PublicKeyCredentialRpEntity, self).__init__(id=id, name=name, icon=icon)

    @property
    def id_hash(self):
        """Return SHA256 hash of the identifier."""
        return sha256(self.id.encode("utf8"))


class PublicKeyCredentialUserEntity(DataObject):
    def __init__(self, id, name, icon=None, display_name=None):
        super(PublicKeyCredentialUserEntity, self).__init__(
            id=id, name=name, icon=icon, display_name=display_name
        )


class PublicKeyCredentialParameters(DataObject):
    def __init__(self, type, alg):
        super(PublicKeyCredentialParameters, self).__init__(type=type, alg=alg)


class PublicKeyCredentialDescriptor(DataObject):
    def __init__(self, type, id, transports=None):
        super(PublicKeyCredentialDescriptor, self).__init__(
            type=type,
            id=id,
            tranports=[AuthenticatorTransport(t) for t in transports]
            if transports
            else None,
        )


class AuthenticatorSelectionCriteria(DataObject):
    def __init__(
        self,
        authenticator_attachment=None,
        require_resident_key=False,
        user_verification=UserVerificationRequirement.PREFERRED,
    ):
        super(AuthenticatorSelectionCriteria, self).__init__(
            authenticator_attachment=AuthenticatorAttachment(authenticator_attachment)
            if authenticator_attachment is not None
            else None,
            require_resident_key=require_resident_key,
            user_verification=UserVerificationRequirement(user_verification),
        )


class PublicKeyCredentialCreationOptions(DataObject):
    def __init__(
        self,
        rp,
        user,
        challenge,
        pub_key_cred_params,
        timeout=None,
        exclude_credentials=None,
        authenticator_selection=None,
        attestation=AttestationConveyancePreference.NONE,
        extensions=None,
    ):
        super(PublicKeyCredentialCreationOptions, self).__init__(
            rp=PublicKeyCredentialRpEntity(rp),
            user=PublicKeyCredentialUserEntity(user),
            challenge=challenge,
            pub_key_cred_params=[
                PublicKeyCredentialParameters(p) for p in pub_key_cred_params
            ],
            timeout=timeout,
            exclude_credentials=[
                PublicKeyCredentialDescriptor(c) for c in exclude_credentials
            ]
            if exclude_credentials
            else None,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_selection
            )
            if authenticator_selection
            else None,
            attestation=AttestationConveyancePreference(attestation),
            extensions=extensions,
        )


class PublicKeyCredentialRequestOptions(DataObject):
    def __init__(
        self,
        challenge,
        timeout=None,
        rp_id=None,
        allow_credentials=None,
        user_verification=UserVerificationRequirement.PREFERRED,
        extensions=None,
    ):
        super(PublicKeyCredentialRequestOptions, self).__init__(
            challenge=challenge,
            timeout=timeout,
            rp_id=rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(c) for c in allow_credentials
            ]
            if allow_credentials
            else None,
            user_verification=UserVerificationRequirement(user_verification),
            extensions=extensions,
        )
