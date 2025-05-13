# Copyright (c) 2024 Yubico AB
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
Utilities for common functionality used by several examples in this directory.
"""

import ctypes
from getpass import getpass

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice

# Support NFC devices if we can
try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

# Use the Windows WebAuthn API if available, and we're not running as admin
try:
    from fido2.client.windows import WindowsClient

    use_winclient = (
        WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin()
    )
except ImportError:
    use_winclient = False


# Handle user interaction via CLI prompts
class CliInteraction(UserInteraction):
    def __init__(self):
        self._pin = None

    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        if not self._pin:
            self._pin = getpass("Enter PIN: ")
        return self._pin

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev


def get_client(predicate=None, **kwargs):
    """Locate a CTAP device suitable for use.

    If running on Windows as non-admin, the predicate check will be skipped and
    a webauthn.dll based client will be returned.

    Extra kwargs will be passed to the constructor of Fido2Client.

    The client will be returned, with the CTAP2 Info, if available.
    """
    if use_winclient:
        return WindowsClient("https://example.com"), None

    user_interaction = kwargs.pop("user_interaction", None) or CliInteraction()

    # Locate a device
    for dev in enumerate_devices():
        # Set up a FIDO 2 client using the origin https://example.com
        client = Fido2Client(
            dev,
            client_data_collector=DefaultClientDataCollector("https://example.com"),
            user_interaction=user_interaction,
            **kwargs,
        )
        # Check if it is suitable for use
        if predicate is None or predicate(client.info):
            return client, client.info
    else:
        raise ValueError("No suitable Authenticator found!")
