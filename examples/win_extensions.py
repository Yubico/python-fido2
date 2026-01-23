# Copyright (c) 2026 Yubico AB
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
Creates a credential and asserts it using the Windows WebAuthn API,
enabling all supported extensions and validating the responses.

This example demonstrates usage of the following extensions:
- credProps: Get credential properties (rk status)
- largeBlob: Store and retrieve large blob data
- prf: Pseudo-random function for deriving secrets
- credBlob: Store small blob data with the credential
- credentialProtectionPolicy: Set credential protection level
- minPinLength: Request minimum PIN length

NOTE: This example is designed to run on Windows with the WebAuthn API available.
If run on a non-Windows platform, or on Windows with elevated privileges, the example
will run using the standard Fido2Client instead.
"""

import os
import sys

from exampleutils import get_client, server, user

from fido2.utils import websafe_decode, websafe_encode

# Set up the server

# Create the Windows client
# Locate a suitable FIDO authenticator
client, info = get_client()

print("=" * 60)
print("Windows WebAuthn Extensions Test")
print("=" * 60)

# Generate test data for extensions
prf_salt = websafe_encode(os.urandom(32))
cred_blob = os.urandom(32)
large_blob_data = b"This is some test data for the large blob extension!"

# =========================================================================
# CREDENTIAL CREATION with all supported extensions
# =========================================================================
print("\n[1] Creating credential with extensions...")

create_options, state = server.register_begin(
    user,
    authenticator_selection={
        "residentKey": "required",
        "userVerification": "required",
    },
    hints=["security-key"],
    extensions={
        # Request credential properties
        "credProps": True,
        # Request large blob support
        "largeBlob": {"support": "preferred"},
        # Enable PRF extension
        "prf": {},
        # Store a credential blob
        "credBlob": cred_blob,
        # Set credential protection policy
        "credentialProtectionPolicy": "userVerificationOptional",
        # Request minimum PIN length
        "minPinLength": True,
    },
)

# Create the credential
result = client.make_credential(create_options.public_key)
auth_data = server.register_complete(state, result)
credential = auth_data.credential_data

print("Credential created successfully!")
print(f"  Credential ID: {credential.credential_id.hex()[:32]}...")

# Validate extension outputs from registration
ext_results = result.client_extension_results
print("\nRegistration extension results:")

# credProps
if "credProps" in ext_results:
    cred_props = ext_results["credProps"]
    print(f"  credProps.rk: {cred_props.get('rk')}")
    if "rk" not in cred_props:
        print("ERROR: credProps should contain 'rk'")
        sys.exit(1)
else:
    print("  credProps: not returned")

# largeBlob
if "largeBlob" in ext_results:
    large_blob = ext_results["largeBlob"]
    lb_supported = large_blob.get("supported", False)
    print(f"  largeBlob.supported: {lb_supported}")
else:
    print("  largeBlob: not returned")
    lb_supported = False

# prf
if "prf" in ext_results:
    prf = ext_results["prf"]
    prf_enabled = prf.get("enabled", False)
    print(f"  prf.enabled: {prf_enabled}")
    if prf_enabled is not True:
        print("ERROR: PRF should be enabled")
        sys.exit(1)
else:
    print("  prf: not returned")
    prf_enabled = False

# credBlob is returned in auth_data.extensions, not client_extension_results
if auth_data.extensions and auth_data.extensions.get("credBlob"):
    print("  credBlob: stored successfully")
else:
    print("  credBlob: not stored (may not be supported)")

# =========================================================================
# ASSERTION with extensions
# =========================================================================
print("\n[2] Authenticating with extensions...")

credentials = [credential]

# Prepare assertion with PRF extension
request_options, state = server.authenticate_begin(
    credentials,
    user_verification="required",
    hints=["security-key"],
    extensions={
        # Use PRF to derive a secret
        "prf": {"eval": {"first": prf_salt}},
        # Get credential blob
        "getCredBlob": True,
    },
)

# Perform the assertion
selection = client.get_assertion(request_options.public_key)
assertion_result = selection.get_response(0)

# Complete authentication
server.authenticate_complete(state, credentials, assertion_result)

print("Authentication successful!")

# Validate assertion extension results
ext_results = assertion_result.client_extension_results
print("\nAssertion extension results:")

# PRF results
if "prf" in ext_results:
    prf_results = ext_results["prf"]
    if "results" in prf_results:
        first_secret = prf_results["results"].get("first")
        print(f"  prf.results.first: {first_secret[:32] if first_secret else None}...")
        if first_secret is None:
            print("ERROR: PRF should return a secret")
            sys.exit(1)
    else:
        print("  prf: no results returned")
else:
    print("  prf: not returned")

# credBlob from authenticator data
auth_data_ext = assertion_result.response.authenticator_data.extensions
if auth_data_ext and "credBlob" in auth_data_ext:
    retrieved_blob = auth_data_ext["credBlob"]
    blob_matches = retrieved_blob == cred_blob
    print(f"  credBlob retrieved: {blob_matches}")
    if blob_matches:
        print(f"    Blob matches original: {cred_blob.hex()[:32]}...")
    else:
        print(f"    Expected: {cred_blob.hex()[:32]}...")
        print(f"    Got: {retrieved_blob.hex()[:32] if retrieved_blob else 'None'}...")
else:
    print("  credBlob: not returned (may not be supported)")

# =========================================================================
# LARGE BLOB: Write and Read (if supported)
# =========================================================================
if lb_supported:
    print("\n[3] Testing large blob write...")

    request_options, state = server.authenticate_begin(
        credentials,
        user_verification="required",
        hints=["security-key"],
        extensions={
            "largeBlob": {"write": websafe_encode(large_blob_data)},
        },
    )

    selection = client.get_assertion(request_options.public_key)
    result = selection.get_response(0)

    ext_results = result.client_extension_results
    if "largeBlob" in ext_results:
        written = ext_results["largeBlob"].get("written", False)
        print(f"  Large blob written: {written}")
        if written is not True:
            print("ERROR: Large blob should be written successfully")
            sys.exit(1)
    else:
        print("  largeBlob: write result not returned")
        written = False

    if written:
        print("\n[4] Testing large blob read...")

        request_options, state = server.authenticate_begin(
            credentials,
            user_verification="required",
            hints=["security-key"],
            extensions={
                "largeBlob": {"read": True},
            },
        )

        selection = client.get_assertion(request_options.public_key)
        result = selection.get_response(0)

        ext_results = result.client_extension_results
        if "largeBlob" in ext_results:
            blob = ext_results["largeBlob"].get("blob")
            if blob:
                retrieved_data = websafe_decode(blob)
                data_matches = retrieved_data == large_blob_data
                print(f"  Large blob read: {data_matches}")
                if not data_matches:
                    print("ERROR: Retrieved large blob should match written data")
                    sys.exit(1)
                print(f"    Data: {retrieved_data.decode('utf-8')}")
            else:
                print("  largeBlob: no blob returned")
        else:
            print("  largeBlob: read result not returned")
else:
    print("\n[3-4] Skipping large blob tests (not supported)")

# =========================================================================
# PRF with two salts
# =========================================================================
if prf_enabled:
    print("\n[5] Testing PRF with two salts...")

    salt2 = websafe_encode(os.urandom(32))

    request_options, state = server.authenticate_begin(
        credentials,
        user_verification="required",
        hints=["security-key"],
        extensions={
            "prf": {
                "evalByCredential": {
                    websafe_encode(credential.credential_id): {
                        "first": prf_salt,
                        "second": salt2,
                    }
                }
            }
        },
    )

    selection = client.get_assertion(request_options.public_key)
    result = selection.get_response(0)

    ext_results = result.client_extension_results
    if "prf" in ext_results and "results" in ext_results["prf"]:
        prf_results = ext_results["prf"]["results"]
        first = prf_results.get("first")
        second = prf_results.get("second")
        print(f"  prf.results.first: {first[:32] if first else None}...")
        print(f"  prf.results.second: {second[:32] if second else None}...")
        if first is None:
            print("ERROR: PRF first result should be returned")
            sys.exit(1)
        if second is None:
            print("ERROR: PRF second result should be returned")
            sys.exit(1)
        if first == second:
            print("ERROR: PRF results should be different for different salts")
            sys.exit(1)
    else:
        print("  prf: results not returned")
else:
    print("\n[5] Skipping PRF two-salt test (not enabled)")

print("\n" + "=" * 60)
print("All tests completed successfully!")
print("=" * 60)
