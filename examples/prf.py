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
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.client import Fido2Client, WindowsClient, UserInteraction
from fido2.utils import websafe_encode
from getpass import getpass
import ctypes
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


uv = "discouraged"
rk = "discouraged"

if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
    # Use the Windows WebAuthn API if available, and we're not running as admin
    client = WindowsClient("https://example.com")
    rk = "required"  # Windows requires resident key for hmac-secret
else:
    # Locate a device
    for dev in enumerate_devices():
        client = Fido2Client(
            dev,
            "https://example.com",
            user_interaction=CliInteraction(),
        )
        if "hmac-secret" in client.info.extensions:
            break
    else:
        print("No Authenticator with the PRF extension found!")
        sys.exit(1)

server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key_requirement=rk,
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
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)
credentials = [auth_data.credential_data]

# PRF result:
if not result.extension_results.get("prf", {}).get("enabled"):
    print("Failed to create credential with PRF", result.extension_results)
    sys.exit(1)

credential = result.attestation_object.auth_data.credential_data
print("New credential created, with the PRF extension.")

# If created with UV, keep using UV
if result.attestation_object.auth_data.is_user_verified():
    uv = "required"

# Prepare parameters for getAssertion
allow_list = [{"type": "public-key", "id": credential.credential_id}]

# Generate a salt for PRF:
salt = os.urandom(32)
print("Authenticate with salt:", salt.hex())


# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
result = client.get_assertion(
    {
        **request_options["publicKey"],
        "extensions": {"prf": {"eval": {"first": salt}}},
    }
)

# Only one cred in allowCredentials, only one response.
result = result.get_response(0)

output1 = result.extension_results["prf"]["results"]["first"]
print("Authenticated, secret:", output1.hex())

# Authenticate again, using two salts to generate two secrets:

# Generate a second salt for PRF:
salt2 = os.urandom(32)
print("Authenticate with second salt:", salt2.hex())

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
result = result.get_response(0)

output = result.extension_results["prf"]["results"]
print("Old secret:", output["first"].hex())
print("New secret:", output["second"].hex())
