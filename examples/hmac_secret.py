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
from __future__ import print_function, absolute_import, unicode_literals

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.extensions import HmacSecretExtension
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
    client = Fido2Client(dev, 'https://example.com')
    if HmacSecretExtension.NAME in client.info.extensions:
        break
else:
    print('No Authenticator with the HmacSecret extension found!')
    sys.exit(1)

use_nfc = CtapPcscDevice and isinstance(dev, CtapPcscDevice)

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

hmac_ext = HmacSecretExtension(client.ctap2)

# Create a credential
if not use_nfc:
    print('\nTouch your authenticator device now...\n')
attestation_object, client_data = client.make_credential(
    rp, user, challenge, extensions=hmac_ext.create_dict(), pin=pin
)

# HmacSecret result:
hmac_result = hmac_ext.results_for(attestation_object.auth_data)

credential = attestation_object.auth_data.credential_data
print('New credential created, with the HmacSecret extension.')

# Prepare parameters for getAssertion
challenge = 'Q0hBTExFTkdF'  # Use a new challenge for each call.
allow_list = [{
    'type': 'public-key',
    'id': credential.credential_id
}]

# Generate a salt for HmacSecret:
salt = os.urandom(32)
print('Authenticate with salt:', b2a_hex(salt))

# Authenticate the credential
if not use_nfc:
    print('\nTouch your authenticator device now...\n')

assertions, client_data = client.get_assertion(
    rp['id'], challenge, allow_list, extensions=hmac_ext.get_dict(salt), pin=pin
)

assertion = assertions[0]  # Only one cred in allowList, only one response.
hmac_res = hmac_ext.results_for(assertion.auth_data)
print('Authenticated, secret:', b2a_hex(hmac_res[0]))

# Authenticate again, using two salts to generate two secrets:

# Generate a second salt for HmacSecret:
salt2 = os.urandom(32)
print('Authenticate with second salt:', b2a_hex(salt2))

if not use_nfc:
    print('\nTouch your authenticator device now...\n')

# The first salt is reused, which should result in the same secret.
assertions, client_data = client.get_assertion(
    rp['id'], challenge, allow_list, extensions=hmac_ext.get_dict(salt, salt2),
    pin=pin
)

assertion = assertions[0]  # Only one cred in allowList, only one response.
hmac_res = hmac_ext.results_for(assertion.auth_data)
print('Old secret:', b2a_hex(hmac_res[0]))
print('New secret:', b2a_hex(hmac_res[1]))
