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
from fido2.cose import ES256, CoseKey
from fido2.server import Fido2Server
from fido2.utils import sha256, websafe_encode

uv = "discouraged"

# Locate a suitable FIDO authenticator
client = get_client(lambda client: "sign" in client.info.extensions)

server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key_requirement="discouraged",
    user_verification=uv,
    authenticator_attachment="cross-platform",
)

message = b"I am a message"
ph_data = sha256(message)

# Create a credential
result = client.make_credential(
    {
        **create_options["publicKey"],
        "extensions": {
            "sign": {
                "generateKey": {"algorithms": [ES256.ALGORITHM], "phData": ph_data}
            }
        },
    }
)

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)
credentials = [auth_data.credential_data]

# PRF result:
sign_result = result.extension_results.sign
print("CREATE sign result", sign_result)
sign_key = sign_result.generated_key
if not sign_key:
    print("Failed to create credential with sign extension", result.extension_results)
    sys.exit(1)
print("New credential created, with the sign extension.")

pk = CoseKey.parse(cbor.decode(sign_key.public_key))  # COSE key in bytes
kh = sign_key.key_handle  # key handle in bytes
print("public key", pk)
print("keyHandle", sign_key["keyHandle"])

print("Test verify signature", sign_result["signature"])
pk.verify(message, sign_result.signature)
print("Signature verified!")

message = b"New message"
ph_data = sha256(message)

# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
result = client.get_assertion(
    {
        **request_options["publicKey"],
        "extensions": {
            "sign": {
                "sign": {
                    "phData": ph_data,
                    "keyHandleByCredential": {
                        websafe_encode(credentials[0].credential_id): kh,
                    },
                },
            }
        },
    }
)

# Only one cred in allowCredentials, only one response.
result = result.get_response(0)

sign_result = result.extension_results.sign
print("GET sign result", sign_result)

print("Test verify signature", sign_result.get("signature"))

pk.verify(message, sign_result.signature)
print("Signature verified!")
