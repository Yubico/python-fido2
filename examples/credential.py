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

from exampleutils import get_client

from fido2.server import Fido2Server

# Locate a suitable FIDO authenticator
client, info = get_client()


# Prefer UV if supported and configured
if info and (info.options.get("uv") or info.options.get("bioEnroll")):
    uv = "preferred"
    print("Authenticator supports User Verification")
else:
    uv = "discouraged"


server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")

user = {"id": b"user_id", "name": "A. User"}


# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user, user_verification=uv, authenticator_attachment="cross-platform"
)

# Create a credential
result = client.make_credential(create_options["publicKey"])

# Complete registration
auth_data = server.register_complete(state, result)
credentials = [auth_data.credential_data]

print("New credential created!")
response = result.response

print("CLIENT DATA:", response.client_data)
print("ATTESTATION OBJECT:", response.attestation_object)
print()
print("CREDENTIAL DATA:", auth_data.credential_data)


# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
results = client.get_assertion(request_options["publicKey"])

# Only one cred in allowCredentials, only one response.
result = results.get_response(0)

# Complete authenticator
server.authenticate_complete(state, credentials, result)

print("Credential authenticated!")
response = result.response

print("CLIENT DATA:", response.client_data)
print()
print("AUTH DATA:", response.authenticator_data)
