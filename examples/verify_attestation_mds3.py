# Copyright (c) 2021 Yubico AB
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
This example shows how to use the FIDO MDS to only allow authenticators for which
metadata is available.

It connects to the first FIDO device found (starts from USB, then looks into NFC),
creates a new credential for it, and verifies that attestation is correctly signed
and valid according to its metadata statement.

On Windows, the native WebAuthn API will be used.

NOTE: You need to retrieve a MDS3 blob to run this example.
See https://fidoalliance.org/metadata/ for more info.
"""

import sys
from base64 import b64decode

from exampleutils import get_client

from fido2.attestation import UntrustedAttestation
from fido2.mds3 import MdsAttestationVerifier, parse_blob
from fido2.server import Fido2Server

# Load the root CA used to sign the Metadata Statement blob
ca = b64decode(
    """
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f"""
)

# Parse the MDS3 blob
if len(sys.argv) != 2:
    print("This example requires a FIDO MDS3 metadata blob, which you can get here:")
    print("https://fidoalliance.org/metadata/")
    print()
    print("USAGE: python verify_attestation_mds3.py blob.jwt")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    metadata = parse_blob(f.read(), ca)

# The verifier is used to query for data in the blob and to verify attestation.
# We could optionally pass a filter function to only allow specific authenticators.
mds = MdsAttestationVerifier(metadata)

# Locate a suitable FIDO authenticator
client, _ = get_client()

# The MDS verifier is passed to the server to verify that new credentials registered
# exist in the MDS blob, else the registration will fail.
server = Fido2Server(
    {"id": "example.com", "name": "Example RP"},
    attestation="direct",
    verify_attestation=mds,
)

user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user, user_verification="discouraged", authenticator_attachment="cross-platform"
)

# Create a credential
result = client.make_credential(create_options["publicKey"])

# Complete registration
try:
    auth_data = server.register_complete(state, result)
    print("Registration completed")

    # mds can also be used to get the metadata for the Authenticator,
    # regardless of if it was used to verify the attestation or not:
    response = result.response
    entry = mds.find_entry(response.attestation_object, response.client_data.hash)
    print("Authenticator description:", entry.metadata_statement.description)
except UntrustedAttestation:
    print("Authenticator metadata not found")
