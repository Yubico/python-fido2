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

from __future__ import annotations

from typing import Any, Mapping, Sequence

from _fido2_native.ctap import NativeLargeBlobs

from .base import Ctap2, Info
from .pin import PinProtocol


class LargeBlobs:
    """Implementation of the CTAP2.1 Large Blobs API.

    Getting a largeBlobKey for a credential is done via the LargeBlobKey extension.

    :param ctap: An instance of a CTAP2 object.
    :param pin_uv_protocol: An instance of a PinUvAuthProtocol.
    :param pin_uv_token: A valid PIN/UV Auth Token for the current CTAP session.
    """

    @staticmethod
    def is_supported(info: Info) -> bool:
        return info.options.get("largeBlobs") is True

    def __init__(
        self,
        ctap: Ctap2,
        pin_uv_protocol: PinProtocol | None = None,
        pin_uv_token: bytes | None = None,
    ):
        if not self.is_supported(ctap.info):
            raise ValueError("Authenticator does not support LargeBlobs")

        max_fragment_length = ctap.info.max_msg_size - 64

        self._native = NativeLargeBlobs(
            ctap._native,
            max_fragment_length,
            pin_uv_protocol.VERSION if pin_uv_protocol else None,
            pin_uv_token,
        )

    def read_blob_array(self) -> Sequence[Mapping[int, Any]]:
        """Gets the entire contents of the Large Blobs array.

        :return: The CBOR decoded list of Large Blobs.
        """
        return self._native.read_blob_array()

    def write_blob_array(self, blob_array: Sequence[Mapping[int, Any]]) -> None:
        """Writes the entire Large Blobs array.

        :param blob_array: A list to write to the Authenticator.
        """
        if not isinstance(blob_array, list):
            raise TypeError("large-blob array must be a list")
        self._native.write_blob_array(blob_array)

    def get_blob(self, large_blob_key: bytes) -> bytes | None:
        """Gets the Large Blob stored for a single credential.

        :param large_blob_key: The largeBlobKey for the credential, or None.
        :returns: The decrypted and deflated value stored for the credential.
        """
        return self._native.get_blob(large_blob_key)

    def put_blob(self, large_blob_key: bytes, data: bytes | None) -> None:
        """Stores a Large Blob for a single credential.

        Any existing entries for the same credential will be replaced.

        :param large_blob_key: The largeBlobKey for the credential.
        :param data: The data to compress, encrypt and store.
        """
        self._native.put_blob(large_blob_key, data)

    def delete_blob(self, large_blob_key: bytes) -> None:
        """Deletes any Large Blob(s) stored for a single credential.

        :param large_blob_key: The largeBlobKey for the credential.
        """
        self._native.delete_blob(large_blob_key)
