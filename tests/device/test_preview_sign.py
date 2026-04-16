import os

import pytest
from fido2 import cbor
from fido2.client import DefaultClientDataCollector, Fido2Client
from fido2.cose import ESP256_SPLIT_ARKG_PLACEHOLDER, CoseKey
from fido2.ctap2.extensions import PreviewSignExtension
from fido2.server import Fido2Server
from fido2.utils import sha256, websafe_decode, websafe_encode

from . import CliInteraction


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if PreviewSignExtension.NAME not in dev_manager.info.extensions:
        pytest.skip("previewSign not supported by authenticator")


def test_client_arkg_p256(device, printer):
    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp, attestation="none")
    user = {"id": b"user_id", "name": "A. User"}
    uv = "discouraged"

    client = Fido2Client(
        device,
        client_data_collector=DefaultClientDataCollector("https://example.com"),
        user_interaction=CliInteraction(printer),
        extensions=[PreviewSignExtension()],
    )

    create_options, state = server.register_begin(
        user,
        resident_key_requirement="discouraged",
        user_verification=uv,
        authenticator_attachment="cross-platform",
    )

    # Create a credential with the sign extension
    result = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {
                PreviewSignExtension.NAME: {
                    "generateKey": {
                        "algorithms": [ESP256_SPLIT_ARKG_PLACEHOLDER],
                    }
                }
            },
        }
    )

    auth_data = server.register_complete(state, result)
    credentials = [auth_data.credential_data]

    sign_result = result.client_extension_results.previewSign
    sign_key = sign_result.generated_key
    assert sign_key is not None

    # Parse the master public key
    pk = CoseKey.parse(cbor.decode(websafe_decode(sign_key["publicKey"])))

    # Verify the fields of sign_key
    att_obj = sign_key.attestation_object
    assert att_obj.auth_data.rp_id_hash == att_obj.auth_data.rp_id_hash
    assert att_obj.auth_data.flags == att_obj.auth_data.flags
    assert att_obj.auth_data.counter == 0
    assert isinstance(att_obj.auth_data.extensions[PreviewSignExtension.NAME][4], int)

    # The "publicKey" above is the same as the inner auth_data
    assert att_obj.auth_data.credential_data.public_key == pk
    # AAGUID should be the same as the one in the main auth_data
    assert att_obj.auth_data.credential_data.aaguid == auth_data.credential_data.aaguid
    # The inner credential_id should be different from the main one
    assert (
        att_obj.auth_data.credential_data.credential_id
        != auth_data.credential_data.credential_id
    )

    # Derive a public key using ARKG
    ctx = b"python-fido2.test_sign_extension_v4"
    ikm = os.urandom(32)
    pk2, args = pk.derive_public_key(ikm, ctx)

    # Prepare a message to sign
    message = b"test message"
    ph_data = sha256(message)

    # Prepare parameters for getAssertion
    request_options, state = server.authenticate_begin(
        credentials, user_verification=uv
    )

    # Authenticate with the sign extension
    result = client.get_assertion(
        {
            **request_options["publicKey"],
            "extensions": {
                PreviewSignExtension.NAME: {
                    "signByCredential": {
                        websafe_encode(credentials[0].credential_id): {
                            "keyHandle": sign_key.key_handle,
                            "tbs": ph_data,
                            "additionalArgs": cbor.encode(args),
                        },
                    },
                }
            },
        }
    )

    response = result.get_response(0)
    sign_result = response.client_extension_results[PreviewSignExtension.NAME]
    signature = sign_result.get("signature")
    assert signature is not None

    # Verify the signature with the derived public key
    pk2.verify(message, websafe_decode(signature))
