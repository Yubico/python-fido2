from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.ctap2.credman import CredentialManagement
from fido2.server import Fido2Server
from . import TEST_PIN

import pytest


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if not CredentialManagement.is_supported(dev_manager.info):
        pytest.skip("CredentialManagement not supported by authenticator")


@pytest.fixture(params=[PinProtocolV1, PinProtocolV2])
def pin_protocol(request, info):
    proto = request.param
    if proto.VERSION not in info.pin_uv_protocols:
        pytest.skip(f"PIN/UV protocol {proto.VERSION} not supported")

    return proto()


def get_credman(ctap2, pin_protocol, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT):
    token = ClientPin(ctap2, pin_protocol).get_pin_token(TEST_PIN, permissions)
    return CredentialManagement(ctap2, pin_protocol, token)


def test_list_and_delete(client, ctap2, pin_protocol):
    # Ensure no credentials exist initially
    credman = get_credman(ctap2, pin_protocol)
    metadata = credman.get_metadata()
    assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 0
    remaining = metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT]
    assert remaining > 0

    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}

    create_options, state = server.register_begin(
        user,
        resident_key_requirement="required",
    )

    # Create a credential
    result = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {"credProps": True},
        }
    )

    # Need new PIN token as old one is expired by make_credential
    credman = get_credman(ctap2, pin_protocol)

    metadata = credman.get_metadata()
    assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1
    assert metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT] < remaining

    # Complete registration
    auth_data = server.register_complete(state, result)
    cred = auth_data.credential_data

    rps = credman.enumerate_rps()
    assert len(rps) == 1

    # Not all keys are required in response, but those that are should match
    for k, v in rps[0][3].items():
        assert rp[k] == v

    rp_id_hash = rps[0][4]
    creds = credman.enumerate_creds(rp_id_hash)
    assert len(creds) == 1
    assert creds[0][6] == user
    assert creds[0][7]["id"] == cred.credential_id
    assert creds[0][8] == cred.public_key

    credman.delete_cred(creds[0][7])
    metadata = credman.get_metadata()
    assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 0
    assert metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT] == remaining


def test_update(client, ctap2, pin_protocol):
    if not CredentialManagement.is_update_supported(ctap2.info):
        pytest.skip("ClientPin update not supported")

    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}

    create_options, state = server.register_begin(
        user,
        resident_key_requirement="required",
    )

    # Create a credential
    result = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {"credProps": True},
        }
    )
    auth_data = server.register_complete(state, result)
    cred_id = {"id": auth_data.credential_data.credential_id, "type": "public-key"}

    # Update user data
    credman = get_credman(ctap2, pin_protocol)
    user2 = {"id": b"user_id", "name": "A. User 2"}
    credman.update_user_info(cred_id, user2)

    rps = credman.enumerate_rps()
    rp_id_hash = rps[0][4]
    creds = credman.enumerate_creds(rp_id_hash)
    assert len(creds) == 1
    assert creds[0][6] == user2
    assert creds[0][7] == cred_id

    # Clean up
    credman.delete_cred(cred_id)


def test_missing_permissions(ctap2, pin_protocol):
    if not ClientPin.is_token_supported(ctap2.info):
        pytest.skip("Permissions not supported")

    credman = get_credman(ctap2, pin_protocol, ClientPin.PERMISSION(0))

    with pytest.raises(CtapError, match="PIN_AUTH_INVALID"):
        credman.get_metadata()
