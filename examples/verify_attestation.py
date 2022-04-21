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
This example shows how to use an AttestationVerifier to only allow credentials signed
by a specific CA.

It connects to the first FIDO device found (starts from USB, then looks into NFC),
creates a new credential for it, and verifies that attestation is signed by the
Yubico FIDO root CA (this will only work for Yubico devices).
On Windows, the native WebAuthn API will be used.
"""
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient, UserInteraction
from fido2.server import Fido2Server
from fido2.attestation import AttestationVerifier
from base64 import b64decode
from getpass import getpass
import sys
import ctypes


# Official Yubico root CA for FIDO Authenticators
YUBICO_CA = b64decode(
    """
MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290
IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk
5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep
8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw
nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT
9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw
LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ
hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN
BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4
MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt
hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k
LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U
sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc
U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==
"""
)


class YubicoAttestationVerifier(AttestationVerifier):
    """Example implementation of an AttestationVerifier.

    This simple example will attempt to verify all trust paths using the Yubico CA.
    A real implementation can use the information in the attestation result, or the
    authenticator data, to determine which CA should be used to verify the path.
    """

    def ca_lookup(self, result, auth_data):
        return YUBICO_CA


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
        use_prompt = True
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


server = Fido2Server(
    {"id": "example.com", "name": "Example RP"},
    attestation="direct",
    verify_attestation=YubicoAttestationVerifier(),
)

user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user, user_verification=uv, authenticator_attachment="cross-platform"
)

# Create a credential
if use_prompt:
    print("\nTouch your authenticator device now...\n")

result = client.make_credential(create_options["publicKey"])

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)
credentials = [auth_data.credential_data]

print("New credential created, attestation verified!")
print("Yubico device AAGUID:", auth_data.credential_data.aaguid.hex())
