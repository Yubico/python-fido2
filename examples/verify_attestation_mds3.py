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
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient, UserInteraction
from fido2.server import Fido2Server
from fido2.attestation import UntrustedAttestation
from fido2.mds3 import parse_blob, MdsAttestationVerifier
from base64 import b64decode
from getpass import getpass
import sys
import ctypes

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

uv = "discouraged"


# Handle user interaction
class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
    # Use the Windows WebAuthn API if available, and we're not running as admin
    client = WindowsClient("https://example.com")
else:
    # Locate a device
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is not None:
        print("Use USB HID channel.")
    else:
        try:
            from fido2.pcsc import CtapPcscDevice

            dev = next(CtapPcscDevice.list_devices(), None)
            print("Use NFC channel.")
        except Exception as e:
            print("NFC channel search error:", e)

    if not dev:
        print("No FIDO device found")
        sys.exit(1)

    # Set up a FIDO 2 client using the origin https://example.com
    client = Fido2Client(dev, "https://example.com", user_interaction=CliInteraction())

    # Prefer UV if supported
    if client.info.options.get("uv"):
        uv = "preferred"
        print("Authenticator supports User Verification")


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
    user, user_verification=uv, authenticator_attachment="cross-platform"
)

# Create a credential
result = client.make_credential(create_options["publicKey"])

# Complete registration
try:
    auth_data = server.register_complete(
        state, result.client_data, result.attestation_object
    )
    print("Registration completed")

    # mds can also be used to get the metadata for the Authenticator,
    # regardless of if it was used to verify the attestation or not:
    entry = mds.find_entry(result.attestation_object, result.client_data.hash)
    print("Authenticator description:", entry.metadata_statement.description)
except UntrustedAttestation:
    print("Authenticator metadata not found")
