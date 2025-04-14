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
from fido2 import cbor
from fido2.server import Fido2Server
from fido2.utils import sha256, websafe_encode, websafe_decode
from fido2.cose import CoseKey
from fido2.arkg import ARKG_P256ADD_ECDH
from exampleutils import get_client
import sys

uv = "discouraged"

# Locate a suitable FIDO authenticator
client, info = get_client(lambda info: "sign" in info.extensions)

server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key_requirement="discouraged",
    user_verification=uv,
    authenticator_attachment="cross-platform",
)

# Create a credential
result = client.make_credential(
    {
        **create_options["publicKey"],
        "extensions": {
            "sign": {"generateKey": {"algorithms": [ARKG_P256ADD_ECDH.ALGORITHM]}}
        },
    }
)

# Complete registration
auth_data = server.register_complete(state, result)
credentials = [auth_data.credential_data]
print("New credential created, with the sign extension.")

# PRF result:
sign_result = result.client_extension_results.get("sign")
print("CREATE sign result", sign_result)
sign_key = sign_result.get("generatedKey")
if not sign_key:
    print(
        "Failed to create credential with sign extension",
        result.client_extension_results,
    )
    sys.exit(1)

# Extension output contains master public key and keyHandle
pk = CoseKey.parse(
    cbor.decode(websafe_decode(sign_key["publicKey"]))
)  # COSE key in bytes
kh = sign_key["keyHandle"]  # key handle in bytes
print("public key", pk)
print("keyHandle from Authenticator", cbor.decode(websafe_decode(kh)))

# Master public key contains blinding and KEM keys
# ARKG derive_public_key uses these
print("Blinding public key", pk.blinding_key)
print("KEM public key", pk.kem_key)

# Arbitrary bytestring used for info
info = b"my-info-here"
# Derived public key to verify with, and kh to send to Authenticator
pk2 = pk.derive_public_key(info)
print("Derived public key", pk2)
ref = pk2.get_ref()
print("COSE Key ref for derived key", ref)
kh = websafe_encode(cbor.encode(ref))

# Prepare a message to sign
message = b"New message"
ph_data = sha256(message)

# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification=uv)


# Authenticate the credential
result = client.get_assertion(
    {
        **request_options["publicKey"],
        # Add extension outputs. We have only 1 credential in allowCredentials
        "extensions": {
            "sign": {
                "sign": {
                    "tbs": ph_data,
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

sign_result = result.client_extension_results["sign"]
print("GET sign result", sign_result)

# Response contains a signature over message
signature = sign_result.get("signature")

print("Test verify signature", signature)
pk2.verify(message, websafe_decode(signature))
print("Signature verified with derived public key!")
