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
"""
from __future__ import print_function, absolute_import, unicode_literals

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.attestation import Attestation
from getpass import getpass
import sys

use_nfc = False

# Locate a device
dev = next(CtapHidDevice.list_devices(), None)
if dev is not None:
    print('Use USB HID channel.')
else:
    try:
        from fido2.pcsc import CtapPcscDevice

        dev = next(CtapPcscDevice.list_devices(), None)
        print('Use NFC channel.')
        use_nfc = True
    except Exception as e:
        print('NFC channel search error:', e)

if not dev:
    print('No FIDO device found')
    sys.exit(1)

# Set up a FIDO 2 client using the origin https://example.com
client = Fido2Client(dev, 'https://example.com')

# Prepare parameters for makeCredential
rp = {'id': 'example.com', 'name': 'Example RP'}
user = {'id': b'user_id', 'name': 'A. User'}
challenge = 'Y2hhbGxlbmdl'

# Prompt for PIN if needed
pin = None
if client.info.options.get('clientPin'):
    pin = getpass('Please enter PIN:')
else:
    print('no pin')

# Create a credential
if not use_nfc:
    print('\nTouch your authenticator device now...\n')
attestation_object, client_data = client.make_credential(
    rp, user, challenge, pin=pin
)


print('New credential created!')

print('CLIENT DATA:', client_data)
print('ATTESTATION OBJECT:', attestation_object)
print()
print('CREDENTIAL DATA:', attestation_object.auth_data.credential_data)

# Verify signature
verifier = Attestation.for_type(attestation_object.fmt)
verifier().verify(
    attestation_object.att_statement,
    attestation_object.auth_data,
    client_data.hash
)
print('Attestation signature verified!')

credential = attestation_object.auth_data.credential_data

# Prepare parameters for getAssertion
challenge = 'Q0hBTExFTkdF'  # Use a new challenge for each call.
allow_list = [{
    'type': 'public-key',
    'id': credential.credential_id
}]

# Authenticate the credential
if not use_nfc:
    print('\nTouch your authenticator device now...\n')

assertions, client_data = client.get_assertion(
    rp['id'], challenge, allow_list, pin=pin
)

print('Credential authenticated!')

assertion = assertions[0]  # Only one cred in allowList, only one response.

print('CLIENT DATA:', client_data)
print()
print('ASSERTION DATA:', assertion)

# Verify signature
assertion.verify(client_data.hash, credential.public_key)
print('Assertion signature verified!')
