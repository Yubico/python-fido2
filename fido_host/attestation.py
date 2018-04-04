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

from .cose import CoseKey, ES256
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import abc


class Attestation(abc.ABC):
    @abc.abstractmethod
    def verify(self, statement, auth_data, client_data_hash):
        pass

    @staticmethod
    def for_type(format):
        return next(cls for cls in Attestation.__subclasses__()
                    if getattr(cls, 'FORMAT') == format)


class NoneAttestation(Attestation):
    FORMAT = 'none'

    def verify(self, statement, auth_data, client_data_hash):
        if statement != {}:
            raise ValueError('None Attestation requires empty statement.')


class FidoU2FAttestation(Attestation):
    FORMAT = 'fido-u2f'

    def verify(self, statement, auth_data, client_data_hash):
        cd = auth_data.credential_data
        pk = b'\x04' + cd.public_key[-2] + cd.public_key[-3]
        FidoU2FAttestation.verify_signature(
            auth_data.rp_id_hash,
            client_data_hash,
            cd.credential_id,
            pk,
            statement['x5c'][0],
            statement['sig']
        )

    @staticmethod
    def verify_signature(app_param, client_param, key_handle, public_key, cert,
                         signature):
        m = b'\0' + app_param + client_param + key_handle + public_key
        certificate = x509.load_der_x509_certificate(cert, default_backend())
        ES256.from_cryptography_key(certificate.public_key()).verify(
            m, signature)


class PackedAttestation(Attestation):
    FORMAT = 'packed'

    def verify(self, statement, auth_data, client_data_hash):
        if 'ecdaaKeyId' in statement:
            raise NotImplementedError('ECDAA not implemented')
        alg = statement['alg']
        x5c = statement.get('x5c')
        if x5c:
            cert = x509.load_der_x509_certificate(x5c[0], default_backend())
            pub_key = CoseKey.for_alg(alg).from_cryptography_key(
                cert.public_key())
            # TODO: Additional verification based on extension, etc.
        else:
            pub_key = CoseKey(auth_data.credential_data.public_key)
            if pub_key.ALGORITHM != alg:
                raise ValueError('Algorithm does not match that of public key!')
        pub_key.verify(auth_data + client_data_hash, statement['sig'])
