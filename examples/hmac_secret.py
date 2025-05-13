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

NOTE: This extension is not enabled by default as direct access to the extension
is now allowed in a browser setting. See also prf.py for an example which uses
the PRF extension which is enabled by default.
"""

import ctypes
import os
import sys

from exampleutils import CliInteraction, enumerate_devices

from fido2.client import DefaultClientDataCollector, Fido2Client
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.server import Fido2Server

# Use the Windows WebAuthn API if available, and we're not running as admin
try:
    from fido2.client.windows import WindowsClient

    use_winclient = (
        WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin()
    )
except ImportError:
    use_winclient = False


uv = "discouraged"

if use_winclient:
    # Use the Windows WebAuthn API if available, and we're not running as admin
    # By default only the PRF extension is allowed, we need to explicitly
    # configure the client to allow hmac-secret
    client = WindowsClient("https://example.com", allow_hmac_secret=True)
else:
    # Locate a device
    for dev in enumerate_devices():
        client = Fido2Client(
            dev,
            client_data_collector=DefaultClientDataCollector("https://example.com"),
            user_interaction=CliInteraction(),
            # By default only the PRF extension is allowed, we need to explicitly
            # configure the client to allow hmac-secret
            extensions=[HmacSecretExtension(allow_hmac_secret=True)],
        )
        if "hmac-secret" in client.info.extensions:
            break
    else:
        print("No Authenticator with the HmacSecret extension found!")
        sys.exit(1)

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
        "extensions": {"hmacCreateSecret": True},
    }
)

# Complete registration
auth_data = server.register_complete(state, result)
credentials = [auth_data.credential_data]

# HmacSecret result:
if result.client_extension_results.get("hmacCreateSecret"):
    print("New credential created, with HmacSecret")
else:
    # This fails on Windows, but we might still be able to use hmac-secret even if
    # the credential wasn't made with it, so keep going
    print("Failed to create credential with HmacSecret, it might not work")

# Generate a salt for HmacSecret:
salt = os.urandom(32)
print("Authenticate with salt:", salt.hex())


# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
result = client.get_assertion(
    {
        **request_options["publicKey"],
        "extensions": {"hmacGetSecret": {"salt1": salt}},
    }
)

# Only one cred in allowCredentials, only one response.
result = result.get_response(0)

output1 = result.client_extension_results.hmac_get_secret.output1
print("Authenticated, secret:", output1.hex())

# Authenticate again, using two salts to generate two secrets:

# Generate a second salt for HmacSecret:
salt2 = os.urandom(32)
print("Authenticate with second salt:", salt2.hex())

# The first salt is reused, which should result in the same secret.

result = client.get_assertion(
    {
        **request_options["publicKey"],
        "extensions": {"hmacGetSecret": {"salt1": salt, "salt2": salt2}},
    }
)

# Only one cred in allowCredentials, only one response.
result = result.get_response(0)

output = result.client_extension_results.hmac_get_secret
print("Old secret:", output.output1.hex())
print("New secret:", output.output2.hex())
