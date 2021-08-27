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
Connects to each FIDO device found, and causes them all to blink until the user
triggers one to select it. A new credential is created for that authenticator,
and the operation is cancelled for the others.
"""
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, ClientError, UserInteraction
from threading import Event, Thread
from getpass import getpass
import sys

# Locate a device
devs = list(CtapHidDevice.list_devices())
if not devs:
    print("No FIDO device found")
    sys.exit(1)


# Handle user interaction
class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


clients = [
    Fido2Client(d, "https://example.com", user_interaction=CliInteraction())
    for d in devs
]

# Prepare parameters for makeCredential
rp = {"id": "example.com", "name": "Example RP"}
user = {"id": b"user_id", "name": "A. User"}
challenge = b"Y2hhbGxlbmdl"
cancel = Event()
selected = None


def select(client):
    global selected
    try:
        client.selection(cancel)
        selected = client
    except ClientError as e:
        if e.code != ClientError.ERR.TIMEOUT:
            raise
        else:
            return
    cancel.set()


print("\nTouch the authenticator you wish to use...\n")

threads = []
for client in clients:
    t = Thread(target=select, args=(client,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

if cancel.is_set():
    print("Authenticator selected, making credential...")

    result = selected.make_credential(
        {
            "rp": rp,
            "user": user,
            "challenge": challenge,
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        },
    )

    print("New credential created!")
    print("ATTESTATION OBJECT:", result.attestation_object)
    print()
    print("CREDENTIAL DATA:", result.attestation_object.auth_data.credential_data)
else:
    print("Operation timed out!")
