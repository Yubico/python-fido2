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

import os

from exampleutils import get_client

from fido2.server import Fido2Server
from fido2.utils import websafe_encode

# Locate a suitable FIDO authenticator
client, _ = get_client(lambda info: "hmac-secret" in info.extensions)

uv = "discouraged"

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
        "extensions": {"prf": {}},
    }
)

# Complete registration
auth_data = server.register_complete(state, result)
credential = auth_data.credential_data

# PRF result:
if result.client_extension_results.get("prf", {}).get("enabled"):
    print("New credential created, with PRF")
else:
    # This fails on Windows, but we might still be able to use prf even if
    # the credential wasn't made with it, so keep going
    print("Failed to create credential with PRF, it might not work")

print("New credential created, with the PRF extension.")

# If created with UV, keep using UV
if auth_data.is_user_verified():
    uv = "required"

# Generate a salt for PRF:
salt = websafe_encode(os.urandom(32))
print("Authenticate with salt:", salt)

# Prepare parameters for getAssertion
credentials = [credential]
request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
result = client.get_assertion(
    {
        **request_options["publicKey"],
        "extensions": {"prf": {"eval": {"first": salt}}},
    }
)

# Only one cred in allowCredentials, only one response.
response = result.get_response(0)

output1 = response.client_extension_results["prf"]["results"]["first"]
print("Authenticated, secret:", output1)

# Authenticate again, using two salts to generate two secrets.

# This time we will use evalByCredential, which can be used if there are multiple
# credentials which use different salts. Here it is not needed, but provided for
# completeness of the example.

# Generate a second salt for PRF:
salt2 = websafe_encode(os.urandom(32))
print("Authenticate with second salt:", salt2)
# The first salt is reused, which should result in the same secret.

result = client.get_assertion(
    {
        **request_options["publicKey"],
        "extensions": {
            "prf": {
                "evalByCredential": {
                    websafe_encode(credential.credential_id): {
                        "first": salt,
                        "second": salt2,
                    }
                }
            }
        },
    }
)

# Only one cred in allowCredentials, only one response.
response = result.get_response(0)

output = response.client_extension_results["prf"]["results"]
print("Old secret:", output["first"])
print("New secret:", output["second"])
