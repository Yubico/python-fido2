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
from fido2.client import Fido2Client
from getpass import getpass
from binascii import b2a_hex
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


# Locate a device
for dev in enumerate_devices():
    client = Fido2Client(dev, "https://example.com")
    if "hmac-secret" in client.info.extensions:
        break
else:
    print("No Authenticator with the HmacSecret extension found!")
    sys.exit(1)

use_nfc = CtapPcscDevice and isinstance(dev, CtapPcscDevice)

# Prepare parameters for makeCredential
rp = {"id": "example.com", "name": "Example RP"}
user = {"id": b"user_id", "name": "A. User"}
challenge = b"Y2hhbGxlbmdl"

# Prompt for PIN if needed
pin = None
if client.info.options.get("clientPin"):
    pin = getpass("Please enter PIN:")
else:
    print("no pin")

# Create a credential with a HmacSecret
if not use_nfc:
    print("\nTouch your authenticator device now...\n")
result = client.make_credential(
    {
        "rp": rp,
        "user": user,
        "challenge": challenge,
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "extensions": {"hmacCreateSecret": True},
    },
    pin=pin,
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
print("Authenticate with salt:", b2a_hex(salt))

# Authenticate the credential
if not use_nfc:
    print("\nTouch your authenticator device now...\n")

result = client.get_assertion(
    {
        "rpId": rp["id"],
        "challenge": challenge,
        "allowCredentials": allow_list,
        "extensions": {"hmacGetSecret": {"salt1": salt}},
    },
    pin=pin,
).get_response(
    0
)  # Only one cred in allowList, only one response.

output1 = result.extension_results["hmacGetSecret"]["output1"]
print("Authenticated, secret:", b2a_hex(output1))

# Authenticate again, using two salts to generate two secrets:

# Generate a second salt for HmacSecret:
salt2 = os.urandom(32)
print("Authenticate with second salt:", b2a_hex(salt2))

if not use_nfc:
    print("\nTouch your authenticator device now...\n")

# The first salt is reused, which should result in the same secret.
result = client.get_assertion(
    {
        "rpId": rp["id"],
        "challenge": challenge,
        "allowCredentials": allow_list,
        "extensions": {"hmacGetSecret": {"salt1": salt, "salt2": salt2}},
    },
    pin=pin,
).get_response(
    0
)  # One cred in allowCredentials, single response.

output = result.extension_results["hmacGetSecret"]
print("Old secret:", b2a_hex(output["output1"]))
print("New secret:", b2a_hex(output["output2"]))
