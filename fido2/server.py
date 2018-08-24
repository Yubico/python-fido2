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

from .rpid import verify_rp_id
from .cose import ES256
from .client import WEBAUTHN_TYPE
from .utils import sha256

import os
import six
from enum import Enum, unique
from cryptography.hazmat.primitives import constant_time


def _verify_origin_for_rp(rp_id):
    return lambda o: verify_rp_id(rp_id, o)


@unique
class ATTESTATION(six.text_type, Enum):
    NONE = 'none'
    INDIRECT = 'indirect'
    DIRECT = 'direct'


@unique
class USER_VERIFICATION(six.text_type, Enum):
    DISCOURAGED = 'discouraged'
    PREFERRED = 'preferred'
    REQUIRED = 'required'


class RelyingParty(object):
    """Representation of relying party data.

    See https://www.w3.org/TR/webauthn/#sctn-rp-credential-params for details.

    :ivar ident: Unique identifier of the relying party,
        see https://www.w3.org/TR/webauthn/#rp-id for details
    :ivar name: Name of the relying party
    :ivar icon: URL with the relying party icon
    """

    def __init__(self, ident, name=None, icon=None):
        self.ident = ident
        self.name = name or ident
        self.icon = icon

    @property
    def id_hash(self):
        """Return SHA256 hash of the identifier."""
        return sha256(self.ident.encode())


class Fido2Server(object):
    """FIDO2 server

    :ivar rp: Relying party data as `RelyingParty` instance.
    """

    def __init__(
            self,
            rp,
            attestation=ATTESTATION.NONE,
            verify_origin=None,
            user_verification=USER_VERIFICATION.PREFERRED
    ):
        self.rp = rp
        self._verify = verify_origin or _verify_origin_for_rp(rp.ident)
        self.timeout = 30
        self.attestation = ATTESTATION(attestation)
        self.allowed_algorithms = [ES256.ALGORITHM]
        self.user_verification = USER_VERIFICATION(user_verification)

    def register_begin(self, user, credentials=None, resident_key=False):
        if not self.allowed_algorithms:
            raise ValueError('Server has no allowed algorithms.')

        challenge = os.urandom(32)

        # Serialize RP
        rp_data = {'id': self.rp.ident, 'name': self.rp.name}
        if self.rp.icon:
            rp_data['icon'] = self.rp.icon

        return {
            'publicKey': {
                'rp': rp_data,
                'user': user,
                'challenge': challenge,
                'pubKeyCredParams': [
                    {
                        'type': 'public-key',
                        'alg': alg
                    } for alg in self.allowed_algorithms
                ],
                'excludeCredentials': [
                    {
                        'type': 'public-key',
                        'id': cred.credential_id
                    } for cred in credentials or []
                ],
                'timeout': int(self.timeout * 1000),
                'attestation': self.attestation,
                'authenticatorSelection': {
                    'requireResidentKey': resident_key,
                    'userVerification': self.user_verification
                }
            }
        }

    def register_complete(self, challenge, client_data, attestation_object):
        if client_data.get('type') != WEBAUTHN_TYPE.MAKE_CREDENTIAL:
            raise ValueError('Incorrect type in ClientData.')
        if not self._verify(client_data.get('origin')):
            raise ValueError('Invalid origin in ClientData.')
        if not constant_time.bytes_eq(challenge, client_data.challenge):
            raise ValueError('Wrong challenge in response.')
        if not constant_time.bytes_eq(self.rp.id_hash,
                                      attestation_object.auth_data.rp_id_hash):
            raise ValueError('Wrong RP ID hash in response.')
        if attestation_object.fmt == ATTESTATION.NONE \
                and self.attestation != ATTESTATION.NONE:
            raise ValueError('Attestation required, but not provided.')
        attestation_object.verify(client_data.hash)

        if self.user_verification is USER_VERIFICATION.REQUIRED and \
           not attestation_object.auth_data.is_user_verified():
            raise ValueError(
                'User verification required, but User verified flag not set.')

        return attestation_object.auth_data

    def authenticate_begin(self, credentials):
        challenge = os.urandom(32)
        return {
            'publicKey': {
                'rpId': self.rp.ident,
                'challenge': challenge,
                'allowCredentials': [
                    {
                        'type': 'public-key',
                        'id': cred.credential_id
                    } for cred in credentials
                ],
                'timeout': int(self.timeout * 1000),
                'userVerification': self.user_verification
            }
        }

    def authenticate_complete(self, credentials, credential_id, challenge,
                              client_data, auth_data, signature):
        if client_data.get('type') != WEBAUTHN_TYPE.GET_ASSERTION:
            raise ValueError('Incorrect type in ClientData.')
        if not self._verify(client_data.get('origin')):
            raise ValueError('Invalid origin in ClientData.')
        if challenge != client_data.challenge:
            raise ValueError('Wrong challenge in response.')
        if not constant_time.bytes_eq(self.rp.id_hash, auth_data.rp_id_hash):
            raise ValueError('Wrong RP ID hash in response.')

        if self.user_verification is USER_VERIFICATION.REQUIRED and \
           not auth_data.is_user_verified():
            raise ValueError(
                'User verification required, but user verified flag not set.')

        for cred in credentials:
            if cred.credential_id == credential_id:
                cred.public_key.verify(auth_data + client_data.hash, signature)
                return cred
        raise ValueError('Unknown credential ID.')
