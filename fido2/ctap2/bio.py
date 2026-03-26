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

import logging
from enum import IntEnum, unique
from threading import Event
from typing import Any, Callable, Mapping, NoReturn

from _fido2_native.ctap import NativeFPBioEnrollment

from ..ctap import CtapError
from .base import Ctap2, Info
from .pin import PinProtocol

logger = logging.getLogger(__name__)


class BioEnrollment:
    @unique
    class RESULT(IntEnum):
        MODALITY = 0x01
        FINGERPRINT_KIND = 0x02
        MAX_SAMPLES_REQUIRED = 0x03
        TEMPLATE_ID = 0x04
        LAST_SAMPLE_STATUS = 0x05
        REMAINING_SAMPLES = 0x06
        TEMPLATE_INFOS = 0x07
        MAX_TEMPLATE_FRIENDLY_NAME = 0x08

    @unique
    class TEMPLATE_INFO(IntEnum):
        ID = 0x01
        NAME = 0x02

    @unique
    class MODALITY(IntEnum):
        FINGERPRINT = 0x01

    @staticmethod
    def is_supported(info: Info) -> bool:
        if "bioEnroll" in info.options:
            return True
        # We also support the Prototype command
        if (
            "FIDO_2_1_PRE" in info.versions
            and "userVerificationMgmtPreview" in info.options
        ):
            return True
        return False

    def __init__(self, ctap: Ctap2, modality: MODALITY):
        if not self.is_supported(ctap.info):
            raise ValueError("Authenticator does not support BioEnroll")

        self.ctap = ctap
        self.modality = self.get_modality()
        if modality != self.modality:
            raise ValueError(f"Device does not support {modality:s}")

    def get_modality(self) -> int:
        """Get bio modality.

        :return: The type of modality supported by the authenticator.
        """
        return self.ctap.bio_enrollment(get_modality=True)[
            BioEnrollment.RESULT.MODALITY
        ]


class CaptureError(Exception):
    def __init__(self, code: int):
        self.code = code
        super().__init__(f"Fingerprint capture error: {code}")


class FPEnrollmentContext:
    """Helper object to perform fingerprint enrollment.

    :param bio: An instance of FPBioEnrollment.
    :param timeout: Optional timeout for fingerprint captures (ms).
    :ivar remaining: The number of (estimated) remaining samples needed.
    :ivar template_id: The ID of the new template (only available after the initial
        sample has been captured).
    """

    def __init__(self, bio: "FPBioEnrollment", timeout: int | None = None):
        self._bio = bio
        self.timeout = timeout
        self.template_id: bytes | None = None
        self.remaining: int | None = None

    def capture(
        self,
        event: Event | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> bytes | None:
        """Capture a fingerprint sample.

        This call will block for up to timeout milliseconds (or indefinitely, if
        timeout not specified) waiting for the user to scan their fingerprint to
        collect one sample.

        :return: None, if more samples are needed, or the template ID if enrollment is
            completed.
        """
        if self.template_id is None:
            self.template_id, status, self.remaining = self._bio.enroll_begin(
                self.timeout, event, on_keepalive
            )
        else:
            status, self.remaining = self._bio.enroll_capture_next(
                self.template_id, self.timeout, event, on_keepalive
            )
        if status != FPBioEnrollment.FEEDBACK.FP_GOOD:
            raise CaptureError(status)
        if self.remaining == 0:
            return self.template_id
        return None

    def cancel(self) -> None:
        """Cancels ongoing enrollment."""
        self._bio.enroll_cancel()
        self.template_id = None


class FPBioEnrollment(BioEnrollment):
    """Implementation of the bio enrollment API.

    NOTE: The get_fingerprint_sensor_info method does not require authentication, and
    can be used by setting pin_uv_protocol and pin_uv_token to None.

    :param ctap: An instance of a CTAP2 object.
    :param pin_uv_protocol: The PIN/UV protocol version used.
    :param pin_uv_token: A valid PIN/UV Auth Token for the current CTAP session.
    """

    @unique
    class CMD(IntEnum):
        ENROLL_BEGIN = 0x01
        ENROLL_CAPTURE_NEXT = 0x02
        ENROLL_CANCEL = 0x03
        ENUMERATE_ENROLLMENTS = 0x04
        SET_NAME = 0x05
        REMOVE_ENROLLMENT = 0x06
        GET_SENSOR_INFO = 0x07

    @unique
    class PARAM(IntEnum):
        TEMPLATE_ID = 0x01
        TEMPLATE_NAME = 0x02
        TIMEOUT_MS = 0x03

    @unique
    class FEEDBACK(IntEnum):
        FP_GOOD = 0x00
        FP_TOO_HIGH = 0x01
        FP_TOO_LOW = 0x02
        FP_TOO_LEFT = 0x03
        FP_TOO_RIGHT = 0x04
        FP_TOO_FAST = 0x05
        FP_TOO_SLOW = 0x06
        FP_POOR_QUALITY = 0x07
        FP_TOO_SKEWED = 0x08
        FP_TOO_SHORT = 0x09
        FP_MERGE_FAILURE = 0x0A
        FP_EXISTS = 0x0B
        FP_DATABASE_FULL = 0x0C
        NO_USER_ACTIVITY = 0x0D
        NO_UP_TRANSITION = 0x0E

        def __str__(self):
            return f"0x{self.value:02X} - {self.name}"

    def __init__(self, ctap: Ctap2, pin_uv_protocol: PinProtocol, pin_uv_token: bytes):
        super().__init__(ctap, BioEnrollment.MODALITY.FINGERPRINT)
        self.pin_uv_protocol = pin_uv_protocol
        self.pin_uv_token = pin_uv_token

        if "bioEnroll" in ctap.info.options:
            cmd_byte = 0x09
        else:
            cmd_byte = 0x40

        self._native = NativeFPBioEnrollment(
            ctap._native.device,
            ctap._native.strict_cbor,
            ctap._native.max_msg_size,
            pin_uv_protocol.VERSION,
            pin_uv_token,
            cmd_byte,
            self.modality,
        )

    @staticmethod
    def _handle_native_error(e: ValueError) -> NoReturn:
        msg = str(e)
        if msg.startswith("CTAP_ERR:"):
            raise CtapError(int(msg.split(":")[1])) from None
        raise

    def get_fingerprint_sensor_info(self) -> Mapping[int, Any]:
        """Get fingerprint sensor info.

        :return: A dict containing FINGERPRINT_KIND and MAX_SAMPLES_REQUIRES.
        """
        try:
            return self._native.get_fingerprint_sensor_info(None, None)
        except ValueError as e:
            self._handle_native_error(e)

    def enroll_begin(
        self,
        timeout: int | None = None,
        event: Event | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> tuple[bytes, FPBioEnrollment.FEEDBACK, int]:
        """Start fingerprint enrollment.

        Starts the process of enrolling a new fingerprint, and will wait for the user
        to scan their fingerprint once to provide an initial sample.

        :param timeout: Optional timeout in milliseconds.
        :return: A tuple containing the new template ID, the sample status, and the
            number of samples remaining to complete the enrollment.
        """
        logger.debug(f"Starting fingerprint enrollment (timeout={timeout})")
        try:
            template_id, status, remaining = self._native.enroll_begin(
                timeout, event, on_keepalive
            )
        except ValueError as e:
            self._handle_native_error(e)
        return (template_id, FPBioEnrollment.FEEDBACK(status), remaining)

    def enroll_capture_next(
        self,
        template_id: bytes,
        timeout: int | None = None,
        event: Event | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> tuple[FPBioEnrollment.FEEDBACK, int]:
        """Continue fingerprint enrollment.

        Continues enrolling a new fingerprint and will wait for the user to scan their
        fingerpring once to provide a new sample.
        Once the number of samples remaining is 0, the enrollment is completed.

        :param template_id: The template ID returned by a call to `enroll_begin`.
        :param timeout: Optional timeout in milliseconds.
        :return: A tuple containing the sample status, and the number of samples
            remaining to complete the enrollment.
        """
        logger.debug(f"Capturing next sample with (timeout={timeout})")
        try:
            status, remaining = self._native.enroll_capture_next(
                template_id, timeout, event, on_keepalive
            )
        except ValueError as e:
            self._handle_native_error(e)
        return (FPBioEnrollment.FEEDBACK(status), remaining)

    def enroll_cancel(self) -> None:
        """Cancel any ongoing fingerprint enrollment."""
        logger.debug("Cancelling fingerprint enrollment.")
        try:
            self._native.enroll_cancel()
        except ValueError as e:
            self._handle_native_error(e)

    def enroll(self, timeout: int | None = None) -> FPEnrollmentContext:
        """Convenience wrapper for doing fingerprint enrollment.

        See FPEnrollmentContext for details.
        :return: An initialized FPEnrollmentContext.
        """
        return FPEnrollmentContext(self, timeout)

    def enumerate_enrollments(self) -> Mapping[bytes, str | None]:
        """Get a dict of enrolled fingerprint templates which maps template ID's to
        their friendly names.

        :return: A dict of enrolled template_id -> name pairs.
        """
        try:
            result = self._native.enumerate_enrollments()
            return {
                t[BioEnrollment.TEMPLATE_INFO.ID]: t[BioEnrollment.TEMPLATE_INFO.NAME]
                for t in result[BioEnrollment.RESULT.TEMPLATE_INFOS]
            }
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_OPTION:
                return {}
            raise
        except ValueError as e:
            self._handle_native_error(e)

    def set_name(self, template_id: bytes, name: str) -> None:
        """Set/Change the friendly name of a previously enrolled fingerprint template.

        :param template_id: The ID of the template to change.
        :param name: A friendly name to give the template.
        """
        logger.debug(f"Changing name of template: {template_id.hex()} to {name}")
        try:
            self._native.set_name(template_id, name)
        except ValueError as e:
            self._handle_native_error(e)
        logger.info("Fingerprint template renamed")

    def remove_enrollment(self, template_id: bytes) -> None:
        """Remove a previously enrolled fingerprint template.

        :param template_id: The Id of the template to remove.
        """
        logger.debug(f"Deleting template: {template_id.hex()}")
        try:
            self._native.remove_enrollment(template_id)
        except ValueError as e:
            self._handle_native_error(e)
        logger.info("Fingerprint template deleted")
