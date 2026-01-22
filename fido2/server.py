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

from __future__ import annotations

import logging
import os
import warnings
from typing import Any, Callable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.primitives import constant_time

from .cose import CoseKey
from .rpid import verify_rp_id
from .utils import websafe_encode
from .webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAttachment,
    AuthenticatorData,
    AuthenticatorSelectionCriteria,
    CollectedClientData,
    CredentialCreationOptions,
    CredentialRequestOptions,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

logger = logging.getLogger(__name__)


VerifyAttestation = Callable[[AttestationObject, bytes], None]
VerifyOrigin = Callable[[str], bool]


def _verify_origin_for_rp(rp_id: str) -> VerifyOrigin:
    return lambda o: verify_rp_id(rp_id, o)


def _validate_challenge(challenge: bytes | None) -> bytes:
    if challenge is None:
        challenge = os.urandom(32)
    else:
        if not isinstance(challenge, bytes):
            raise TypeError("Custom challenge must be of type 'bytes'.")
        if len(challenge) < 16:
            raise ValueError("Custom challenge length must be >= 16.")
    return challenge


def to_descriptor(
    credential: AttestedCredentialData, transports=None
) -> PublicKeyCredentialDescriptor:
    """Converts an AttestedCredentialData to a PublicKeyCredentialDescriptor.

    :param credential: AttestedCredentialData containing the credential ID to use.
    :param transports: Optional list of AuthenticatorTransport strings to add to the
        descriptor.
    :return: A descriptor of the credential, for use with register_begin or
        authenticate_begin.
    :rtype: PublicKeyCredentialDescriptor
    """
    return PublicKeyCredentialDescriptor(
        type=PublicKeyCredentialType.PUBLIC_KEY,
        id=credential.credential_id,
        transports=transports,
    )


def _wrap_credentials(
    creds: Sequence[AttestedCredentialData | PublicKeyCredentialDescriptor] | None,
) -> Sequence[PublicKeyCredentialDescriptor] | None:
    if creds is None:
        return None
    return [
        (
            to_descriptor(c)
            if isinstance(c, AttestedCredentialData)
            else PublicKeyCredentialDescriptor.from_dict(c)
        )
        for c in creds
    ]


def _ignore_attestation(
    attestation_object: AttestationObject, client_data_hash: bytes
) -> None:
    """Ignore attestation."""


def _merge_dicts(primary: Mapping[str, Any], secondary: Mapping[str, Any]) -> dict:
    result = dict(secondary)
    for key, value in primary.items():
        # Existing key with dict value in both primary and secondary are merged
        # Note: lists are not merged
        if key in result and isinstance(value, dict) and isinstance(result[key], dict):
            result[key] = _merge_dicts(value, result[key])
        else:
            result[key] = value
    return result


# TODO: 3.0 Remove deprecated properties and parameters
# TODO: 3.0 Replace state with CredentialCreationOptions
class Fido2Server:
    """FIDO2 server.

    :param rp: Relying party data as `PublicKeyCredentialRpEntity` instance.
    :param attestation: (optional) Requirement on authenticator attestation.
    :param verify_origin: (optional) Alternative function to validate an origin.
    :param verify_attestation: (optional) function to validate attestation, which is
        invoked with attestation_object and client_data_hash. It should return nothing
        and raise an exception on failure. By default, attestation is ignored.
        Attestation is also ignored if `attestation` is set to `none`.
    :param creation_defaults: (optional) Default parameters for `register_begin`.
    :param assertion_defaults: (optional) Default parameters for `authenticate_begin`.
    """

    def __init__(
        self,
        rp: PublicKeyCredentialRpEntity,
        attestation: AttestationConveyancePreference | None = None,
        verify_origin: VerifyOrigin | None = None,
        verify_attestation: VerifyAttestation | None = None,
        creation_defaults: Mapping[str, Any] | None = None,
        assertion_defaults: Mapping[str, Any] | None = None,
    ):
        self.rp = PublicKeyCredentialRpEntity.from_dict(rp)
        assert self.rp.id is not None  # noqa: S101
        self._verify = verify_origin or _verify_origin_for_rp(self.rp.id)
        self._verify_attestation = verify_attestation or _ignore_attestation
        self._creation_defaults = dict(creation_defaults) if creation_defaults else {}
        if "pub_key_cred_params" not in self._creation_defaults:
            self._creation_defaults["pub_key_cred_params"] = [
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY, alg=alg
                )
                for alg in CoseKey.supported_algorithms()
            ]
        if attestation:
            warnings.warn(
                "Deprecated: set attestation in creation_defaults instead.",
                DeprecationWarning,
            )
            self._creation_defaults["attestation"] = AttestationConveyancePreference(
                attestation
            )

        self._assertion_defaults = (
            dict(assertion_defaults) if assertion_defaults else {}
        )

        # Validate default options
        PublicKeyCredentialCreationOptions(
            rp=self.rp,
            user=PublicKeyCredentialUserEntity(id=b"", name="", display_name=""),
            challenge=b"",
            exclude_credentials=None,
            **self._creation_defaults,
        )
        PublicKeyCredentialRequestOptions(
            challenge=b"",
            rp_id=self.rp.id,
            allow_credentials=None,
            **self._assertion_defaults,
        )

        logger.debug(f"Fido2Server initialized for RP: {self.rp}")

    @property
    def allowed_algorithms(self) -> list[PublicKeyCredentialParameters]:
        """List of allowed PublicKeyCredentialParameters."""
        warnings.warn(
            "Deprecated: do not read allowed_algorithms.",
            DeprecationWarning,
        )
        return self._creation_defaults["pub_key_cred_params"]

    @property
    def attestation(self) -> AttestationConveyancePreference | None:
        """Attestation conveyance preference."""
        warnings.warn(
            "Deprecated: do not read attestation.",
            DeprecationWarning,
        )
        return self._creation_defaults.get("attestation")

    @property
    def timeout(self) -> int | None:
        """Timeout in milliseconds for operations."""
        warnings.warn(
            "Deprecated: do not read timeout.",
            DeprecationWarning,
        )
        return self._creation_defaults.get("timeout")

    @timeout.setter
    def timeout(self, value: int | None) -> None:
        warnings.warn(
            "Deprecated: use creation_defaults and assertion_defaults to set timeout.",
            DeprecationWarning,
        )
        self._creation_defaults["timeout"] = value
        self._assertion_defaults["timeout"] = value

    def register_begin(
        self,
        user: PublicKeyCredentialUserEntity,
        credentials: (
            Sequence[AttestedCredentialData | PublicKeyCredentialDescriptor] | None
        ) = None,
        # TODO: 3.0 Remove these three params in favor of using authenticator_selection
        resident_key_requirement: ResidentKeyRequirement | None = None,
        user_verification: UserVerificationRequirement | None = None,
        authenticator_attachment: AuthenticatorAttachment | None = None,
        challenge: bytes | None = None,
        **kwargs,
    ) -> tuple[CredentialCreationOptions, Any]:
        """Return a PublicKeyCredentialCreationOptions registration object and
        the internal state dictionary that needs to be passed as is to the
        corresponding `register_complete` call.

        :param user: The dict containing the user data.
        :param credentials: The list of previously registered credentials, these can be
            of type AttestedCredentialData, or PublicKeyCredentialDescriptor.
        :param resident_key_requirement: The desired RESIDENT_KEY_REQUIREMENT level.
        :param user_verification: The desired USER_VERIFICATION level.
        :param authenticator_attachment: The desired AUTHENTICATOR_ATTACHMENT
            or None to not provide a preference (and get both types).
        :param challenge: A custom challenge to sign and verify or None to use
            OS-specific random bytes.
        :return: Registration data, internal state."""

        challenge = _validate_challenge(challenge)
        descriptors = _wrap_credentials(credentials)

        kwargs = _merge_dicts(kwargs, self._creation_defaults)

        # TODO: 3.0 Remove in favor of using authenticator_selection
        if any(
            (
                authenticator_attachment,
                resident_key_requirement,
                user_verification,
            )
        ):
            warnings.warn(
                "Deprecated: parameters authenticator_attachment, "
                "resident_key_requirement, and user_verification are deprecated; use "
                "authenticator_selection instead.",
                DeprecationWarning,
            )
            selection = AuthenticatorSelectionCriteria.from_dict(
                kwargs.pop("authenticator_selection", {})
            )
            selection = AuthenticatorSelectionCriteria(
                authenticator_attachment=authenticator_attachment
                or selection.authenticator_attachment,
                resident_key=resident_key_requirement or selection.resident_key,
                user_verification=user_verification or selection.user_verification,
            )
            kwargs["authenticator_selection"] = selection

        options = CredentialCreationOptions(
            public_key=PublicKeyCredentialCreationOptions(
                rp=self.rp,
                user=user,
                challenge=challenge,
                exclude_credentials=descriptors,
                **kwargs,
            )
        )
        if not options.public_key.pub_key_cred_params:
            raise ValueError("Request has no allowed algorithms.")

        logger.debug(
            "Starting new registration, existing credentials: "
            + ", ".join(d.id.hex() for d in descriptors or [])
        )

        return (options, dict(options))

    def register_complete(
        self,
        state: dict,
        response: RegistrationResponse | Mapping[str, Any],
    ) -> AuthenticatorData:
        """Verify the correctness of the registration data received from
        the client.

        :param state: The state data returned by the corresponding
            `register_begin`.
        :param response: The registration response from the client.
        :return: The authenticator data
        """
        options = CredentialCreationOptions.from_dict(state).public_key

        registration = RegistrationResponse.from_dict(response)
        client_data = registration.response.client_data
        attestation_object = registration.response.attestation_object

        if client_data.type != CollectedClientData.TYPE.CREATE:
            raise ValueError("Incorrect type in CollectedClientData.")
        if not self._verify(client_data.origin):
            raise ValueError("Invalid origin in CollectedClientData.")
        if not constant_time.bytes_eq(options.challenge, client_data.challenge):
            raise ValueError("Wrong challenge in response.")
        if not constant_time.bytes_eq(
            self.rp.id_hash or b"", attestation_object.auth_data.rp_id_hash
        ):
            raise ValueError("Wrong RP ID hash in response.")
        if not attestation_object.auth_data.is_user_present():
            raise ValueError("User Present flag not set.")

        if (
            options.authenticator_selection
            and options.authenticator_selection.user_verification
            == UserVerificationRequirement.REQUIRED
            and not attestation_object.auth_data.is_user_verified()
        ):
            raise ValueError(
                "User verification required, but User Verified flag not set."
            )

        # Validate the attestation statement
        if options.attestation not in (None, AttestationConveyancePreference.NONE):
            logger.debug(f"Verifying attestation of type {attestation_object.fmt}")
            self._verify_attestation(attestation_object, client_data.hash)
        # We simply ignore attestation if self.attestation == 'none', as not all
        # clients strip the attestation.

        auth_data = attestation_object.auth_data

        # Make sure the algorithm is allowed
        assert auth_data.credential_data is not None  # noqa: S101
        key_alg = auth_data.credential_data.public_key.ALGORITHM
        if key_alg not in [p.alg for p in options.pub_key_cred_params]:
            raise ValueError(f"Unsupported public key algorithm: {key_alg}")

        logger.info(
            "New credential registered: "
            + auth_data.credential_data.credential_id.hex()
        )
        return auth_data

    def authenticate_begin(
        self,
        credentials: (
            Sequence[AttestedCredentialData | PublicKeyCredentialDescriptor] | None
        ) = None,
        # TODO: 3.0 Remove in favor of using user_verification in kwargs
        user_verification: UserVerificationRequirement | None = None,
        challenge: bytes | None = None,
        **kwargs,
    ) -> tuple[CredentialRequestOptions, Any]:
        """Return a PublicKeyCredentialRequestOptions assertion object and the internal
        state dictionary that needs to be passed as is to the corresponding
        `authenticate_complete` call.

        :param credentials: The list of previously registered credentials, these can be
            of type AttestedCredentialData, or PublicKeyCredentialDescriptor.
        :param user_verification: The desired USER_VERIFICATION level.
        :param challenge: A custom challenge to sign and verify or None to use
            OS-specific random bytes.
        :return: Assertion data, internal state."""
        challenge = _validate_challenge(challenge)
        descriptors = _wrap_credentials(credentials)
        kwargs = _merge_dicts(kwargs, self._assertion_defaults)
        if user_verification is not None:
            kwargs["user_verification"] = user_verification

        if descriptors is None:
            logger.debug("Starting new authentication without credentials")
        else:
            logger.debug(
                "Starting new authentication, for credentials: "
                + ", ".join(d.id.hex() for d in descriptors)
            )

        options = CredentialRequestOptions(
            public_key=PublicKeyCredentialRequestOptions(
                challenge=challenge,
                rp_id=self.rp.id,
                allow_credentials=descriptors,
                **kwargs,
            )
        )

        return (options, dict(options))

    def authenticate_complete(
        self,
        state: dict,
        credentials: Sequence[AttestedCredentialData],
        response: AuthenticationResponse | Mapping[str, Any],
    ) -> AttestedCredentialData:
        """Verify the correctness of the assertion data received from
        the client.

        :param state: The state data returned by the corresponding
            `register_begin`.
        :param credentials: The list of previously registered credentials.
        :param credential_id: The credential id from the client response.
        :param client_data: The client data.
        :param auth_data: The authenticator data.
        :param signature: The signature provided by the client."""

        options = CredentialRequestOptions.from_dict(state).public_key

        authentication = AuthenticationResponse.from_dict(response)
        credential_id = authentication.raw_id
        client_data = authentication.response.client_data
        auth_data = authentication.response.authenticator_data
        signature = authentication.response.signature

        if client_data.type != CollectedClientData.TYPE.GET:
            raise ValueError("Incorrect type in CollectedClientData.")
        if not self._verify(client_data.origin):
            raise ValueError("Invalid origin in CollectedClientData.")
        if not constant_time.bytes_eq(options.challenge, client_data.challenge):
            raise ValueError("Wrong challenge in response.")
        if not constant_time.bytes_eq(self.rp.id_hash or b"", auth_data.rp_id_hash):
            raise ValueError("Wrong RP ID hash in response.")
        if not auth_data.is_user_present():
            raise ValueError("User Present flag not set.")

        if (
            options.user_verification == UserVerificationRequirement.REQUIRED
            and not auth_data.is_user_verified()
        ):
            raise ValueError(
                "User verification required, but user verified flag not set."
            )

        for cred in credentials:
            if cred.credential_id == credential_id:
                try:
                    cred.public_key.verify(auth_data + client_data.hash, signature)
                except _InvalidSignature:
                    raise ValueError("Invalid signature.")
                logger.info(f"Credential authenticated: {credential_id.hex()}")
                return cred
        raise ValueError("Unknown credential ID.")

    @staticmethod
    def _make_internal_state(
        challenge: bytes,
        **kwargs,
    ):
        return {"challenge": websafe_encode(challenge), **kwargs}
