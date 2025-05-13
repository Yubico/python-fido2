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

"""
Connects to the first FIDO device found (starts from USB, then looks into NFC),
creates a new credential for it, and authenticates the credential.
This works with both FIDO 2.0 devices as well as with U2F devices.
On Windows, the native WebAuthn API will be used.
"""

import sys

from exampleutils import get_client

from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode

# Locate a suitable FIDO authenticator
client, info = get_client(lambda info: "largeBlobKey" in info.extensions)

# LargeBlob requires UV if it is configured
uv = "discouraged"
if info.options.get("clientPin"):
    uv = "required"


server = Fido2Server({"id": "example.com", "name": "Example RP"})
user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key_requirement="required",
    user_verification=uv,
    authenticator_attachment="cross-platform",
)

print("Creating a credential with LargeBlob support...")

# Create a credential
result = client.make_credential(
    {
        **create_options["publicKey"],
        # Enable largeBlob
        "extensions": {"largeBlob": {"support": "required"}},
    }
)

# Complete registration
auth_data = server.register_complete(state, result)
credentials = [auth_data.credential_data]

if auth_data.is_user_verified():
    # The WindowsClient doesn't know about authenticator config until now
    uv = "required"

if not result.client_extension_results.get("largeBlob", {}).get("supported"):
    print("Credential does not support largeBlob, failure!")
    sys.exit(1)

print("Credential created! Writing a blob...")

# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
selection = client.get_assertion(
    {
        **request_options["publicKey"],
        # Write a large blob
        "extensions": {
            "largeBlob": {"write": websafe_encode(b"Here is some data to store!")}
        },
    }
)

# Only one cred in allowCredentials, only one response.
result = selection.get_response(0)
if not result.client_extension_results.get("largeBlob", {}).get("written"):
    print("Failed to write blob!")
    sys.exit(1)

print("Blob written! Reading back the blob...")

# Authenticate the credential
selection = client.get_assertion(
    {
        **request_options["publicKey"],
        # Read the blob
        "extensions": {"largeBlob": {"read": True}},
    }
)

# Only one cred in allowCredentials, only one response.
result = selection.get_response(0)
print(
    "Read blob:", websafe_decode(result.client_extension_results["largeBlob"]["blob"])
)
