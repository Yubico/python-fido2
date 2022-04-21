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
Connects to the first FIDO device found which supports the HmacSecret extension,
creates a new credential for it with the extension enabled, and uses it to
derive two separate secrets.
"""
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction
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
    if "hmac-secret" in client.info.extensions:
        break
else:
    print("No Authenticator with the HmacSecret extension found!")
    sys.exit(1)

# Prepare parameters for makeCredential
rp = {"id": "example.com", "name": "Example RP"}
user = {"id": b"user_id", "name": "A. User"}
challenge = b"Y2hhbGxlbmdl"

# Create a credential with a HmacSecret
result = client.make_credential(
    {
        "rp": rp,
        "user": user,
        "challenge": challenge,
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "extensions": {"hmacCreateSecret": True},
    },
)

# HmacSecret result:
if not result.extension_results.get("hmacCreateSecret"):
    print("Failed to create credential with HmacSecret")
    sys.exit(1)

credential = result.attestation_object.auth_data.credential_data
print("New credential created, with the HmacSecret extension.")

# Prepare parameters for getAssertion
challenge = b"Q0hBTExFTkdF"  # Use a new challenge for each call.
allow_list = [{"type": "public-key", "id": credential.credential_id}]

# Generate a salt for HmacSecret:
salt = os.urandom(32)
print("Authenticate with salt:", salt.hex())

# Authenticate the credential
result = client.get_assertion(
    {
        "rpId": rp["id"],
        "challenge": challenge,
        "allowCredentials": allow_list,
        "extensions": {"hmacGetSecret": {"salt1": salt}},
    },
).get_response(
    0
)  # Only one cred in allowList, only one response.

output1 = result.extension_results["hmacGetSecret"]["output1"]
print("Authenticated, secret:", output1.hex())

# Authenticate again, using two salts to generate two secrets:

# Generate a second salt for HmacSecret:
salt2 = os.urandom(32)
print("Authenticate with second salt:", salt2.hex())

# The first salt is reused, which should result in the same secret.
result = client.get_assertion(
    {
        "rpId": rp["id"],
        "challenge": challenge,
        "allowCredentials": allow_list,
        "extensions": {"hmacGetSecret": {"salt1": salt, "salt2": salt2}},
    },
).get_response(
    0
)  # One cred in allowCredentials, single response.

output = result.extension_results["hmacGetSecret"]
print("Old secret:", output["output1"].hex())
print("New secret:", output["output2"].hex())
