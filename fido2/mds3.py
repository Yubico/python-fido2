# Copyright (c) 2022 Yubico AB
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


from .webauthn import AttestationObject
from .attestation import (
    Attestation,
    UntrustedAttestation,
    verify_x509_chain,
    AttestationVerifier,
)
from .utils import websafe_decode, _CamelCaseDataObject
from .cose import CoseKey

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dataclasses import dataclass, field
from enum import Enum, unique
from datetime import date
from base64 import b64decode, b64encode
from contextvars import ContextVar
from typing import Sequence, Mapping, Any, Optional, Callable

import json
import logging

logger = logging.getLogger(__name__)


@dataclass(eq=False)
class Version(_CamelCaseDataObject):
    major: int
    minor: int


@dataclass(eq=False)
class RogueListEntry(_CamelCaseDataObject):
    sk: bytes
    date: int


@dataclass(eq=False)
class BiometricStatusReport(_CamelCaseDataObject):
    cert_level: int
    modality: str
    effective_date: int
    certification_descriptor: str
    certificate_number: str
    certification_policy_version: str
    certification_requirements_version: str


@dataclass(eq=False)
class CodeAccuracyDescriptor(_CamelCaseDataObject):
    base: int
    min_length: int
    max_retries: Optional[int] = None
    block_slowdown: Optional[int] = None


@dataclass(eq=False)
class BiometricAccuracyDescriptor(_CamelCaseDataObject):
    self_attested_frr: Optional[float] = field(
        default=None, metadata=dict(name="selfAttestedFRR")
    )
    self_attested_far: Optional[float] = field(
        default=None, metadata=dict(name="selfAttestedFAR")
    )
    max_templates: Optional[int] = None
    max_retries: Optional[int] = None
    block_slowdown: Optional[int] = None


@dataclass(eq=False)
class PatternAccuracyDescriptor(_CamelCaseDataObject):
    min_complexity: int
    max_retries: Optional[int] = None
    block_slowdown: Optional[int] = None


@dataclass(eq=False)
class VerificationMethodDescriptor(_CamelCaseDataObject):
    user_verification_method: Optional[str] = None
    ca_desc: Optional[CodeAccuracyDescriptor] = None
    ba_desc: Optional[BiometricAccuracyDescriptor] = None
    pa_desc: Optional[PatternAccuracyDescriptor] = None


@dataclass(eq=False)
class RgbPaletteEntry(_CamelCaseDataObject):
    r: int
    g: int
    b: int


@dataclass(eq=False)
class DisplayPngCharacteristicsDescriptor(_CamelCaseDataObject):
    width: int
    height: int
    bit_depth: int
    color_type: int
    compression: int
    filter: int
    interlace: int
    plte: Optional[Sequence[RgbPaletteEntry]] = None


@dataclass(eq=False)
class EcdaaTrustAnchor(_CamelCaseDataObject):
    x: str = field(metadata=dict(name="X"))
    y: str = field(metadata=dict(name="Y"))
    c: str
    sx: str
    sy: str
    g1_curve: str = field(metadata=dict(name="G1Curve"))


@unique
class AuthenticatorStatus(str, Enum):
    NOT_FIDO_CERTIFIED = "NOT_FIDO_CERTIFIED"
    FIDO_CERTIFIED = "FIDO_CERTIFIED"
    USER_VERIFICATION_BYPASS = "USER_VERIFICATION_BYPASS"
    ATTESTATION_KEY_COMPROMISE = "ATTESTATION_KEY_COMPROMISE"
    USER_KEY_REMOTE_COMPROMISE = "USER_KEY_REMOTE_COMPROMISE"
    USER_KEY_PHYSICAL_COMPROMISE = "USER_KEY_PHYSICAL_COMPROMISE"
    UPDATE_AVAILABLE = "UPDATE_AVAILABLE"
    REVOKED = "REVOKED"
    SELF_ASSERTION_SUBMITTED = "SELF_ASSERTION_SUBMITTED"
    FIDO_CERTIFIED_L1 = "FIDO_CERTIFIED_L1"
    FIDO_CERTIFIED_L1plus = "FIDO_CERTIFIED_L1plus"
    FIDO_CERTIFIED_L2 = "FIDO_CERTIFIED_L2"
    FIDO_CERTIFIED_L2plus = "FIDO_CERTIFIED_L2plus"
    FIDO_CERTIFIED_L3 = "FIDO_CERTIFIED_L3"
    FIDO_CERTIFIED_L3plus = "FIDO_CERTIFIED_L3plus"


@dataclass(eq=False)
class StatusReport(_CamelCaseDataObject):
    status: AuthenticatorStatus
    effective_date: Optional[date] = field(
        metadata=dict(
            deserialize=date.fromisoformat,
            serialize=lambda x: x.isoformat(),
        ),
        default=None,
    )
    authenticator_version: Optional[int] = None
    certificate: Optional[bytes] = field(
        metadata=dict(deserialize=b64decode, serialize=lambda x: b64encode(x).decode()),
        default=None,
    )
    url: Optional[str] = None
    certification_descriptor: Optional[str] = None
    certificate_number: Optional[str] = None
    certification_policy_version: Optional[str] = None
    certification_requirements_version: Optional[str] = None


@dataclass(eq=False)
class ExtensionDescriptor(_CamelCaseDataObject):
    fail_if_unknown: bool = field(metadata=dict(name="fail_if_unknown"))
    id: str
    tag: Optional[int] = None
    data: Optional[str] = None


@dataclass(eq=False)
class MetadataStatement(_CamelCaseDataObject):
    description: str
    authenticator_version: int
    schema: int
    upv: Sequence[Version]
    attestation_types: Sequence[str]
    user_verification_details: Sequence[Sequence[VerificationMethodDescriptor]] = field(
        metadata=dict(serialize=lambda xss: [[dict(x) for x in xs] for xs in xss])
    )
    key_protection: int
    matcher_protection: int
    attachment_hint: int
    tc_display: int
    attestation_root_certificates: Sequence[bytes] = field(
        metadata=dict(
            deserialize=lambda xs: [b64decode(x) for x in xs],
            serialize=lambda xs: [b64encode(x).decode() for x in xs],
        )
    )
    legal_header: Optional[str] = None
    aaid: Optional[str] = None
    aaguid: Optional[bytes] = field(
        metadata=dict(
            deserialize=lambda x: bytes.fromhex(x.replace("-", "")),
            serialize=lambda x: "-".join(
                y.hex() for y in (x[:4], x[4:6], x[6:8], x[8:10], x[10:])
            ),
        ),
        default=None,
    )
    attestation_certificate_key_identifiers: Optional[Sequence[bytes]] = field(
        metadata=dict(
            deserialize=lambda xs: [bytes.fromhex(x) for x in xs],
            serialize=lambda xs: [x.hex() for x in xs],
        ),
        default=None,
    )
    alternative_descriptions: Optional[Mapping[str, str]] = None
    protocol_family: Optional[str] = None
    authentication_algorithms: Optional[Sequence[str]] = None
    public_key_alg_and_encodings: Optional[Sequence[str]] = None
    is_key_restricted: Optional[bool] = None
    is_fresh_user_verification_required: Optional[bool] = None
    crypto_strength: Optional[int] = None
    operating_env: Optional[str] = None
    tc_display_content_type: Optional[str] = None
    tc_display_png_characteristics: Optional[
        Sequence[DisplayPngCharacteristicsDescriptor]
    ] = field(
        metadata=dict(name="tcDisplayPNGCharacteristics"),
        default=None,
    )
    ecdaa_trust_anchors: Optional[Sequence[EcdaaTrustAnchor]] = None
    icon: Optional[str] = None
    supported_extensions: Optional[Sequence[ExtensionDescriptor]] = None
    authenticator_get_info: Optional[Mapping[str, Any]] = None


@dataclass(eq=False)
class MetadataBlobPayloadEntry(_CamelCaseDataObject):
    status_reports: Sequence[StatusReport]
    time_of_last_status_change: date = field(
        metadata=dict(
            deserialize=date.fromisoformat,
            serialize=lambda x: x.isoformat(),
        )
    )
    aaid: Optional[str] = None
    aaguid: Optional[bytes] = field(
        metadata=dict(
            deserialize=lambda x: bytes.fromhex(x.replace("-", "")),
            serialize=lambda x: "-".join(
                y.hex() for y in (x[:4], x[4:6], x[6:8], x[8:10], x[10:])
            ),
        ),
        default=None,
    )
    attestation_certificate_key_identifiers: Optional[Sequence[bytes]] = field(
        metadata=dict(
            deserialize=lambda xs: [bytes.fromhex(x) for x in xs],
            serialize=lambda xs: [x.hex() for x in xs],
        ),
        default=None,
    )
    metadata_statement: Optional[MetadataStatement] = None
    biometric_status_reports: Optional[Sequence[BiometricStatusReport]] = None
    rogue_list_url: Optional[str] = field(
        metadata=dict(name="rogueListURL"), default=None
    )
    rogue_list_hash: Optional[bytes] = field(
        metadata=dict(
            deserialize=bytes.fromhex,
            serialize=lambda x: x.hex(),
        ),
        default=None,
    )


@dataclass(eq=False)
class MetadataBlobPayload(_CamelCaseDataObject):
    legal_header: str
    no: int
    next_update: date = field(
        metadata=dict(
            deserialize=date.fromisoformat,
            serialize=lambda x: x.isoformat(),
        )
    )
    entries: Sequence[MetadataBlobPayloadEntry]


_last_entry: ContextVar[Optional[MetadataBlobPayloadEntry]] = ContextVar("_last_entry")


class MdsAttestationVerifier(AttestationVerifier):
    """MDS3 implementation of an AttestationVerifier.

    The entry_filter is an optional predicate used to filter which metadata entries to
    allow. When set, all entries must pass this filter for the attestation to be
    considered valid.

    :param blob: The MetadataBlobPayload to query for device metadata.
    :param entry_filter: An optional filter to exclude entries from the result.
    :param attestation_types: A list of Attestation types to support.
    """

    def __init__(
        self,
        blob: MetadataBlobPayload,
        entry_filter: Optional[Callable[[MetadataBlobPayloadEntry], bool]] = None,
        attestation_types: Sequence[Attestation] = None,
    ):
        super().__init__(attestation_types)
        entries = (
            [e for e in blob.entries if entry_filter(e)]
            if entry_filter
            else blob.entries
        )
        self._aaguid_table = {e.aaguid: e for e in entries if e.aaguid}
        self._ski_table = {
            ski: e
            for e in entries
            for ski in e.attestation_certificate_key_identifiers or []
        }

    def find_entry_by_aaguid(self, aaguid: bytes) -> Optional[MetadataBlobPayloadEntry]:
        """Find an entry by AAGUID.

        Returns a MetadataBlobPayloadEntry with a matching aaguid field, if found.
        """
        return self._aaguid_table.get(aaguid)

    def find_entry_by_chain(
        self, certificate_chain: Sequence[bytes]
    ) -> Optional[MetadataBlobPayloadEntry]:
        """Find an entry by trust chain.

        Returns a MetadataBlobPayloadEntry containing an
        attestationCertificateKeyIdentifier which matches one of the certificates in the
        given chain, if found.
        """
        for der in certificate_chain:
            cert = x509.load_der_x509_certificate(der, default_backend())
            ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
            if ski in self._ski_table:
                return self._ski_table[ski]
        return None

    def ca_lookup(self, result, auth_data):
        aaguid = auth_data.credential_data.aaguid
        if aaguid and aaguid != b"\0" * 16:
            logging.debug(f"Using AAGUID: {aaguid.hex()} to look up metadata")
            entry = self.find_entry_by_aaguid(aaguid)
        else:
            logging.debug("Using trust_path chain to look up metadata")
            entry = self.find_entry_by_chain(result.trust_path)

        if entry:
            logging.debug(f"Found entry: {entry}")

            # Figure out which root to use
            if not entry.metadata_statement:
                logging.warn("Matched entry has no metadata_statement, can't validate!")
                return None

            issuer = x509.load_der_x509_certificate(
                result.trust_path[-1], default_backend()
            ).issuer

            for root in entry.metadata_statement.attestation_root_certificates:
                subject = x509.load_der_x509_certificate(
                    root, default_backend()
                ).subject
                if subject == issuer:
                    _last_entry.set(entry)
                    return root
            logger.info(f"No attestation root matching subject: {subject}")
        return None

    def find_entry(
        self, attestation_object: AttestationObject, client_data_hash: bytes
    ) -> Optional[MetadataBlobPayloadEntry]:
        """Lookup a Metadata entry based on an Attestation.

        Returns the first Metadata entry matching the given attestation and verifies it.
        """
        token = _last_entry.set(None)
        try:
            self.verify_attestation(attestation_object, client_data_hash)
            return _last_entry.get()
        except UntrustedAttestation:
            return None
        finally:
            _last_entry.reset(token)


def parse_blob(blob: bytes, trust_root: Optional[bytes]) -> MetadataBlobPayload:
    """Parse a FIDO MDS3 blob and verifies its signature.

    See https://fidoalliance.org/metadata/ for details on obtaining the blob, as well as
    the CA certificate used to sign it.

    The resulting MetadataBlobPayload can be used to lookup metadata entries for
    specific Authenticators, or used with the MdsAttestationVerifier to verify that the
    attestation from a WebAuthn registration is valid and included in the metadata blob.

    NOTE: If trust_root is None, the signature of the blob will NOT be verified!
    """
    message, signature_b64 = blob.rsplit(b".", 1)
    signature = websafe_decode(signature_b64)
    header, payload = (json.loads(websafe_decode(x)) for x in message.split(b"."))

    if trust_root is not None:
        # Verify trust chain
        chain = [b64decode(c) for c in header.get("x5c", [])]
        chain += [trust_root]
        verify_x509_chain(chain)

        # Verify blob signature using leaf
        leaf = x509.load_der_x509_certificate(chain[0], default_backend())
        public_key = CoseKey.for_name(header["alg"]).from_cryptography_key(
            leaf.public_key()
        )
        print("Verifier", public_key)
        public_key.verify(message, signature)
    else:
        logger.warn("Parsing MDS blob without trust anchor, CONTENT IS NOT VERIFIED!")

    return MetadataBlobPayload.from_dict(payload)
