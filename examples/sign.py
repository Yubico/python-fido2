# Copyright (c) 2024 Yubico AB
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

"""
Connects to the first FIDO device found which supports the PRF extension,
creates a new credential for it with the extension enabled, and uses it to
derive two separate secrets.
"""

import sys

from exampleutils import get_client

from fido2 import cbor
from fido2.cose import (
    CoseKey,
    EcsdsaBls12_381_Sha256,
)
from fido2.ctap2.extensions import SignExtension
from fido2.server import Fido2Server
from fido2.utils import sha256, websafe_encode

ESP256_2P = -70009  # Placeholder value

uv = "discouraged"

# Locate a suitable FIDO authenticator
client, info = get_client(lambda info: SignExtension.NAME in info.extensions)

server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key_requirement="discouraged",
    user_verification=uv,
    authenticator_attachment="cross-platform",
)

algorithms = [
    ESP256_2P,
    EcsdsaBls12_381_Sha256.ALGORITHM,
]

# Create a credential
result = client.make_credential(
    {
        **create_options["publicKey"],
        "extensions": {SignExtension.NAME: {"generateKey": {"algorithms": algorithms}}},
    }
)

# Complete registration
auth_data = server.register_complete(state, result)
credentials = [auth_data.credential_data]

# PRF result:
sign_result = result.client_extension_results.previewSign
print("CREATE sign result", sign_result)
sign_key = sign_result.generated_key
if not sign_key:
    print(
        "Failed to create credential with sign extension",
        result.client_extension_results,
    )
    sys.exit(1)
print("New credential created, with the sign extension.")
if sign_key.algorithm not in algorithms:
    print("Got unexpected algorithm in response:", sign_key.algorithm)
    sys.exit(1)


pk = CoseKey.parse(cbor.decode(sign_key.public_key))  # COSE key in bytes
print("public key", pk)

kh = sign_key.key_handle
print("keyHandle", kh)

message = b"I am a message"
is_prehash_alg = sign_key.algorithm in [ESP256_2P]
data = sha256(message) if is_prehash_alg else message

# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
result = client.get_assertion(
    {
        **request_options["publicKey"],
        "extensions": {
            SignExtension.NAME: {
                "signByCredential": {
                    websafe_encode(credentials[0].credential_id): {
                        "keyHandle": kh,
                        "tbs": data,
                    },
                },
            }
        },
    }
)

# Only one cred in allowCredentials, only one response.
result = result.get_response(0)

sign_result = result.client_extension_results.previewSign
print("GET sign result", sign_result)

print("Test verify signature", sign_result.get("signature"))

pk.verify(message, sign_result.signature)
print("Signature verified!")
