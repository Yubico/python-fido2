# Copyright (c) 2020 Yubico AB
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
Connects to the first FIDO device found which supports the CredBlob extension,
creates a new credential for it with the extension enabled, and stores some data.
"""
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction
from fido2.server import Fido2Server
from getpass import getpass
import sys
import os

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev


# Handle user interaction
class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


# Locate a device
for dev in enumerate_devices():
    client = Fido2Client(dev, "https://example.com", user_interaction=CliInteraction())
    if "credBlob" in client.info.extensions:
        break
else:
    print("No Authenticator with the CredBlob extension found!")
    sys.exit(1)

# Prefer UV token if supported
uv = "discouraged"
if client.info.options.get("pinUvAuthToken") or client.info.options.get("uv"):
    uv = "preferred"
    print("Authenticator supports UV token")


server = Fido2Server({"id": "example.com", "name": "Example RP"})
user = {"id": b"user_id", "name": "A. User"}
# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key_requirement="required",
    user_verification=uv,
    authenticator_attachment="cross-platform",
)

# Add CredBlob extension, attach data
blob = os.urandom(32)  # 32 random bytes
options = dict(create_options["publicKey"])
options["extensions"] = {"credBlob": blob}

# Create a credential
result = client.make_credential(options)

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)
credentials = [auth_data.credential_data]


# CredBlob result:
if not auth_data.extensions.get("credBlob"):
    print("Credential was registered, but credBlob was NOT saved.")
    sys.exit(1)

print("New credential created, with the CredBlob extension.")

# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin()
options = dict(request_options["publicKey"])
options["extensions"] = {"getCredBlob": True}

# Authenticate the credential
# Only one cred in allowCredentials, only one response.
result = client.get_assertion(options).get_response(0)

blob_res = result.authenticator_data.extensions.get("credBlob")

if blob == blob_res:
    print("Authenticated, got correct blob:", blob.hex())
else:
    print(
        "Authenticated, got incorrect blob! (was %s, expected %s)"
        % (blob_res.hex(), blob.hex())
    )
    sys.exit(1)
