# Copyright (c) 2020 Yubico AB
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
Connects to the first FIDO device found over USB, and attempts to enroll a new
fingerprint. This requires that a PIN is already set.

NOTE: This uses a draft bio enrollment specification which is not yet final.
Consider this highly experimental.
"""

import sys
from getpass import getpass

from fido2.ctap2 import CaptureError, Ctap2, FPBioEnrollment
from fido2.ctap2.bio import BioEnrollment
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice

pin = None
uv = "discouraged"

for dev in CtapHidDevice.list_devices():
    try:
        ctap = Ctap2(dev)
        if BioEnrollment.is_supported(ctap.info):
            break
    except Exception:  # noqa: S112
        continue
else:
    print("No Authenticator supporting bioEnroll found")
    sys.exit(1)

if not ctap.info.options.get("clientPin"):
    print("PIN not set for the device!")
    sys.exit(1)

# Authenticate with PIN
print("Preparing to enroll a new fingerprint.")
pin = getpass("Please enter PIN: ")
client_pin = ClientPin(ctap)
pin_token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.BIO_ENROLL)
bio = FPBioEnrollment(ctap, client_pin.protocol, pin_token)

print(bio.enumerate_enrollments())

# Start enrollment
enroller = bio.enroll()
template_id = None
while template_id is None:
    print("Press your fingerprint against the sensor now...")
    try:
        template_id = enroller.capture()
        print(enroller.remaining, "more scans needed.")
    except CaptureError as e:
        print(e)
bio.set_name(template_id, "Example")

print("Fingerprint registered successfully with ID:", template_id)
