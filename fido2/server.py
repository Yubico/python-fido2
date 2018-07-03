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
from .utils import sha256

import os
from cryptography.hazmat.primitives import constant_time


def _verify_origin_for_rp(rp_id):
    return lambda o: verify_rp_id(rp_id, o)


class Fido2Server(object):
    def __init__(self, rp_id, attestation=None, verify_origin=None):
        self.rp_id = rp_id
        self._verify = verify_origin or _verify_origin_for_rp(rp_id)
        self.timeout = 30
        self.attestation = attestation or 'none'
        self.cred_algorithms = [ES256.ALGORITHM]

    def register_begin(self, rp, user, credentials=None):
        challenge = os.urandom(32)
        return {
            'publicKey': {
                'rp': rp,
                'user': user,
                'challenge': challenge,
                'pubKeyCredParams': [
                    {
                        'type': 'public-key',
                        'alg': alg
                    } for alg in self.cred_algorithms
                ],
                'excludeCredentials': [
                    {
                        'type': 'public-key',
                        'id': cred.credential_id
                    } for cred in credentials or []
                ],
                'timeout': int(self.timeout * 1000),
                'attestation': self.attestation
            }
        }

    def register_complete(self, challenge, client_data, attestation_object):
        if client_data.get('type') != 'webauthn.create':
            raise ValueError('Incorrect type in ClientData.')
        if not self._verify(client_data.get('origin')):
            raise ValueError('Invalid origin in ClientData.')
        if not constant_time.bytes_eq(challenge, client_data.challenge):
            raise ValueError('Wrong challenge in response.')
        if not constant_time.bytes_eq(sha256(self.rp_id.encode()),
                                      attestation_object.auth_data.rp_id_hash):
            raise ValueError('Wrong RP ID hash in response.')
        # TODO: Ensure that we're using an acceptable attestation format.
        attestation_object.verify(client_data.hash)
        return attestation_object.auth_data

    def authenticate_begin(self, rp_id, credentials):
        challenge = os.urandom(32)
        return {
            'publicKey': {
                'rpId': rp_id,
                'challenge': challenge,
                'allowCredentials': [
                    {
                        'type': 'public-key',
                        'id': cred.credential_id
                    } for cred in credentials
                ],
                'timeout': int(self.timeout * 1000)
            }
        }

    def authenticate_complete(self, credentials, credential_id, challenge,
                              client_data, auth_data, signature):
        if client_data.get('type') != 'webauthn.get':
            raise ValueError('Incorrect type in ClientData.')
        if not self._verify(client_data.get('origin')):
            raise ValueError('Invalid origin in ClientData.')
        if challenge != client_data.challenge:
            raise ValueError('Wrong challenge in response.')
        if not constant_time.bytes_eq(sha256(self.rp_id.encode()),
                                      auth_data.rp_id_hash):
            raise ValueError('Wrong RP ID hash in response.')

        for cred in credentials:
            if cred.credential_id == credential_id:
                cred.public_key.verify(auth_data + client_data.hash, signature)
                return cred
        raise ValueError('Unknown credential ID.')
