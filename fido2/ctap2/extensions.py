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

from __future__ import absolute_import, unicode_literals

from .pin import ClientPin
from enum import Enum, unique
import abc


class Ctap2Extension(abc.ABC):
    """Base class for Ctap2 extensions.
    Subclasses are instantiated for a single request, if the Authenticator supports
    the extension.
    """

    def __init__(self, ctap):
        self.ctap = ctap

    def is_supported(self):
        return self.NAME in self.ctap.info.extensions

    def process_create_input(self, inputs):
        """Returns a value to include in the authenticator extension input,
        or None.
        """
        return None

    def process_create_output(self, auth_data):
        """Return client extension output given auth_data, or None."""
        return None

    def process_get_input(self, inputs):
        """Returns a value to include in the authenticator extension input,
        or None.
        """
        return None

    def process_get_output(self, auth_data):
        """Return client extension output given auth_data, or None."""
        return None


class HmacSecretExtension(Ctap2Extension):
    """
    Implements the hmac-secret CTAP2 extension.
    """

    NAME = "hmac-secret"
    SALT_LEN = 32

    def __init__(self, ctap, pin_protocol=None):
        super(HmacSecretExtension, self).__init__(ctap)
        self.pin_protocol = pin_protocol

    def process_create_input(self, inputs):
        if self.is_supported() and inputs.get("hmacCreateSecret") is True:
            return True

    def process_create_output(self, auth_data):
        if auth_data.extensions.get(self.NAME):
            return {"hmacCreateSecret": True}

    def process_get_input(self, inputs):
        data = self.is_supported() and inputs.get("hmacGetSecret")
        if not data:
            return

        salt1 = data["salt1"]
        salt2 = data.get("salt2", b"")
        if not (
            len(salt1) == HmacSecretExtension.SALT_LEN
            and (not salt2 or len(salt2) == HmacSecretExtension.SALT_LEN)
        ):
            raise ValueError("Invalid salt length")

        client_pin = ClientPin(self.ctap, self.pin_protocol)
        key_agreement, self.shared_secret = client_pin._get_shared_secret()
        if self.pin_protocol is None:
            self.pin_protocol = client_pin.protocol

        salt_enc = self.pin_protocol.encrypt(self.shared_secret, salt1 + salt2)
        salt_auth = self.pin_protocol.authenticate(self.shared_secret, salt_enc)

        return {
            1: key_agreement,
            2: salt_enc,
            3: salt_auth,
            4: self.pin_protocol.VERSION,
        }

    def process_get_output(self, auth_data):
        value = auth_data.extensions.get(self.NAME)

        decrypted = self.pin_protocol.decrypt(self.shared_secret, value)
        output1 = decrypted[: HmacSecretExtension.SALT_LEN]
        output2 = decrypted[HmacSecretExtension.SALT_LEN :]
        outputs = {"output1": output1}
        if output2:
            outputs["output2"] = output2

        return {"hmacGetSecret": outputs}


class LargeBlobKeyExtension(Ctap2Extension):
    """
    Implements the Large Blob Key CTAP2 extension.
    """

    NAME = "largeBlobKey"

    def process_create_input(self, inputs):
        if self.is_supported() and inputs.get("largeBlobKey") is True:
            return True

    def process_get_input(self, inputs):
        if self.is_supported() and inputs.get("largeBlobKey") is True:
            return True


class CredBlobExtension(Ctap2Extension):
    """
    Implements the Credential Blob CTAP2 extension.
    """

    NAME = "credBlob"

    def process_create_input(self, inputs):
        blob = self.is_supported() and inputs.get("credBlob")
        if blob and len(blob) <= self.ctap.info.max_cred_blob_length:
            return blob

    def process_get_input(self, inputs):
        if self.is_supported() and inputs.get("getCredBlob") is True:
            return True


class CredProtectExtension(Ctap2Extension):
    """
    Implements the Credential Protection CTAP2 extension.
    """

    @unique
    class POLICY(Enum):
        OPTIONAL = "userVerificationOptional"
        OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList"
        REQUIRED = "userVerificationRequired"

    ALWAYS_RUN = True
    NAME = "credProtect"

    def process_create_input(self, inputs):
        policy = inputs.get("credentialProtectionPolicy")
        if policy:
            index = list(CredProtectExtension.POLICY).index(policy)
            enforce = inputs.get("enforceCredentialProtectionPolicy", False)
            if enforce and not self.is_supported() and index > 0:
                raise ValueError("Authenticator does not support Credential Protection")
            return index + 1


class MinPinLengthExtension(Ctap2Extension):
    """
    Implements the Minimum PIN Length CTAP2 extension.
    """

    NAME = "minPinLength"

    def process_create_input(self, inputs):
        if self.is_supported() and inputs.get(self.NAME) is True:
            return True
