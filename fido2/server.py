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
from typing import Any, Callable, Mapping, Sequence

from _fido2_native.server import Fido2Server as NativeFido2Server

from . import cbor
from .utils import websafe_decode, websafe_encode
from .webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAttachment,
    AuthenticatorData,
    AuthenticatorSelectionCriteria,
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


class Fido2Server:
    """FIDO2 server.

    :param rp: Relying party data as `PublicKeyCredentialRpEntity` instance.
    :param attestation: (optional) Requirement on authenticator attestation.
    :param verify_origin: (optional) Alternative function to validate an origin.
    :param verify_attestation: (optional) function to validate attestation, which is
        invoked with attestation_object and client_data_hash. It should return nothing
        and raise an exception on failure. By default, attestation is ignored.
        Attestation is also ignored if `attestation` is set to `none`.
    """

    def __init__(
        self,
        rp: PublicKeyCredentialRpEntity,
        attestation: AttestationConveyancePreference | None = None,
        verify_origin: VerifyOrigin | None = None,
        verify_attestation: VerifyAttestation | None = None,
    ):
        self.rp = PublicKeyCredentialRpEntity.from_dict(rp)
        assert self.rp.id is not None  # noqa: S101
        self.timeout = None
        self.attestation = AttestationConveyancePreference(attestation)

        # Wrap verify_attestation to adapt (bytes, bytes) -> (AttestationObject, bytes)
        native_att_cb = None
        if verify_attestation is not None:

            def _att_adapter(att_obj_bytes: bytes, client_data_hash: bytes) -> None:
                verify_attestation(AttestationObject(att_obj_bytes), client_data_hash)

            native_att_cb = _att_adapter

        self._native = NativeFido2Server(
            self.rp.id,
            self.rp.name,
            str(self.attestation) if self.attestation else None,
            verify_origin,
            native_att_cb,
        )
        self.allowed_algorithms = [
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY, alg=alg
            )
            for alg in self._native.allowed_algorithms
        ]
        logger.debug(f"Fido2Server initialized for RP: {self.rp}")

    def register_begin(
        self,
        user: PublicKeyCredentialUserEntity,
        credentials: (
            Sequence[AttestedCredentialData | PublicKeyCredentialDescriptor] | None
        ) = None,
        resident_key_requirement: ResidentKeyRequirement | None = None,
        user_verification: UserVerificationRequirement | None = None,
        authenticator_attachment: AuthenticatorAttachment | None = None,
        challenge: bytes | None = None,
        extensions=None,
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
        if not self.allowed_algorithms:
            raise ValueError("Server has no allowed algorithms.")

        challenge = self._native.generate_challenge(challenge)
        descriptors = _wrap_credentials(credentials)
        state = self._make_internal_state(challenge, user_verification)
        logger.debug(
            "Starting new registration, existing credentials: "
            + ", ".join(d.id.hex() for d in descriptors or [])
        )

        return (
            CredentialCreationOptions(
                public_key=PublicKeyCredentialCreationOptions(
                    rp=self.rp,
                    user=PublicKeyCredentialUserEntity.from_dict(user),
                    challenge=challenge,
                    pub_key_cred_params=self.allowed_algorithms,
                    timeout=self.timeout,
                    exclude_credentials=descriptors,
                    authenticator_selection=(
                        AuthenticatorSelectionCriteria(
                            authenticator_attachment=authenticator_attachment,
                            resident_key=resident_key_requirement,
                            user_verification=user_verification,
                        )
                        if any(
                            (
                                authenticator_attachment,
                                resident_key_requirement,
                                user_verification,
                            )
                        )
                        else None
                    ),
                    attestation=self.attestation,
                    extensions=extensions,
                )
            ),
            state,
        )

    def register_complete(
        self,
        state,
        response: RegistrationResponse | Mapping[str, Any],
    ) -> AuthenticatorData:
        """Verify the correctness of the registration data received from
        the client.

        :param state: The state data returned by the corresponding
            `register_begin`.
        :param response: The registration response from the client.
        :return: The authenticator data
        """
        registration = RegistrationResponse.from_dict(response)
        client_data = registration.response.client_data
        attestation_object = registration.response.attestation_object

        self._native.register_complete(
            bytes(client_data),
            bytes(attestation_object),
            websafe_decode(state["challenge"]),
            state["user_verification"] == UserVerificationRequirement.REQUIRED,
        )

        auth_data = attestation_object.auth_data
        assert auth_data.credential_data is not None  # noqa: S101
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
        user_verification: UserVerificationRequirement | None = None,
        challenge: bytes | None = None,
        extensions=None,
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
        challenge = self._native.generate_challenge(challenge)
        descriptors = _wrap_credentials(credentials)
        state = self._make_internal_state(challenge, user_verification)
        if descriptors is None:
            logger.debug("Starting new authentication without credentials")
        else:
            logger.debug(
                "Starting new authentication, for credentials: "
                + ", ".join(d.id.hex() for d in descriptors)
            )

        return (
            CredentialRequestOptions(
                public_key=PublicKeyCredentialRequestOptions(
                    challenge=challenge,
                    timeout=self.timeout,
                    rp_id=self.rp.id,
                    allow_credentials=descriptors,
                    user_verification=user_verification,
                    extensions=extensions,
                )
            ),
            state,
        )

    def authenticate_complete(
        self,
        state,
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

        authentication = AuthenticationResponse.from_dict(response)
        credential_id = authentication.raw_id
        client_data = authentication.response.client_data
        auth_data = authentication.response.authenticator_data
        signature = authentication.response.signature

        cred_list = [
            (bytes(c.credential_id), cbor.encode(dict(c.public_key)))
            for c in credentials
        ]

        index = self._native.authenticate_complete(
            bytes(client_data),
            bytes(auth_data),
            websafe_decode(state["challenge"]),
            state["user_verification"] == UserVerificationRequirement.REQUIRED,
            cred_list,
            bytes(credential_id),
            bytes(signature),
        )

        logger.info(f"Credential authenticated: {credential_id.hex()}")
        return credentials[index]

    @staticmethod
    def _make_internal_state(
        challenge: bytes, user_verification: UserVerificationRequirement | None
    ):
        return {
            "challenge": websafe_encode(challenge),
            "user_verification": user_verification,
        }
