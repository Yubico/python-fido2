import pytest

from fido2.ctap import CtapError
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.server import Fido2Server

from . import TEST_PIN


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if not CredentialManagement.is_supported(dev_manager.info):
        pytest.skip("CredentialManagement not supported by authenticator")


def get_credman(ctap2, pin_protocol, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT):
    token = ClientPin(ctap2, pin_protocol).get_pin_token(TEST_PIN, permissions)
    return CredentialManagement(ctap2, pin_protocol, token)


def test_list_and_delete(client, ctap2, pin_protocol, algorithm):
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
            "pubKeyCredParams": [algorithm],
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
    assert cred.public_key[3] == algorithm["alg"]

    rps = credman.enumerate_rps()
    assert len(rps) == 1

    # Not all keys are required in response, but those that are should match
    for k, v in rps[0][CredentialManagement.RESULT.RP].items():
        assert rp[k] == v

    rp_id_hash = rps[0][CredentialManagement.RESULT.RP_ID_HASH]
    creds = credman.enumerate_creds(rp_id_hash)
    assert len(creds) == 1
    assert creds[0][CredentialManagement.RESULT.USER] == user
    assert (
        creds[0][CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == cred.credential_id
    )
    assert creds[0][CredentialManagement.RESULT.PUBLIC_KEY] == cred.public_key
    assert not creds[0].get(CredentialManagement.RESULT.THIRD_PARTY_PAYMENT)

    credman.delete_cred(creds[0][CredentialManagement.RESULT.CREDENTIAL_ID])
    metadata = credman.get_metadata()
    assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 0
    assert metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT] == remaining


def test_update(client, ctap2, pin_protocol):
    if not CredentialManagement.is_update_supported(ctap2.info):
        pytest.skip("ClientPin update not supported")

    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User", "displayName": "Display Name"}

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

    credman = get_credman(ctap2, pin_protocol)
    rps = credman.enumerate_rps()
    rp_id_hash = rps[0][CredentialManagement.RESULT.RP_ID_HASH]

    # Check user data
    creds = credman.enumerate_creds(rp_id_hash)
    assert len(creds) == 1

    # Authenticators may or may not store name/displayName
    stores_name = "name" in creds[0][CredentialManagement.RESULT.USER]
    stores_display_name = "displayName" in creds[0][CredentialManagement.RESULT.USER]

    if not stores_name:
        del user["name"]
    if not stores_display_name:
        del user["displayName"]

    assert creds[0][CredentialManagement.RESULT.USER] == user

    # Update user data
    user2 = {"id": b"user_id"}
    if stores_name:
        user2["name"] = "A. User 2"
    if stores_display_name:
        user2["displayName"] = "Display Name 2"

    credman.update_user_info(cred_id, user2)

    creds = credman.enumerate_creds(rp_id_hash)
    assert len(creds) == 1
    assert creds[0][CredentialManagement.RESULT.USER] == user2
    assert creds[0][CredentialManagement.RESULT.CREDENTIAL_ID] == cred_id
    assert not creds[0].get(CredentialManagement.RESULT.THIRD_PARTY_PAYMENT)

    # Test deleting fields
    user3 = {"id": b"user_id"}
    credman.update_user_info(cred_id, user3)
    creds = credman.enumerate_creds(rp_id_hash)
    assert len(creds) == 1
    assert creds[0][CredentialManagement.RESULT.USER] == user3
    assert creds[0][CredentialManagement.RESULT.CREDENTIAL_ID] == cred_id
    assert not creds[0].get(CredentialManagement.RESULT.THIRD_PARTY_PAYMENT)

    # Clean up
    credman.delete_cred(cred_id)


def test_missing_permissions(ctap2, pin_protocol):
    if not ClientPin.is_token_supported(ctap2.info):
        pytest.skip("Permissions not supported")

    credman = get_credman(ctap2, pin_protocol, ClientPin.PERMISSION(0))

    with pytest.raises(CtapError, match="PIN_AUTH_INVALID"):
        credman.get_metadata()


def test_read_only_management(dev_manager, pin_protocol):
    if not CredentialManagement.is_readonly_supported(dev_manager.info):
        pytest.skip("Persistent PUAT not supported")

    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}

    create_options, state = server.register_begin(
        user,
        resident_key_requirement="required",
    )

    token = ClientPin(dev_manager.ctap2, pin_protocol).get_pin_token(
        TEST_PIN, ClientPin.PERMISSION.PERSISTENT_CREDENTIAL_MGMT
    )

    # Get cred_store_state, enc_identifier before reconnect
    cred_state = dev_manager.ctap2.get_info().get_cred_store_state(token)
    ident = dev_manager.ctap2.get_info().get_identifier(token)

    # Create a credential
    result = dev_manager.client.make_credential(create_options["publicKey"])
    auth_data = server.register_complete(state, result)
    cred_id = {"id": auth_data.credential_data.credential_id, "type": "public-key"}
    rp_id_hash = server.rp.id_hash

    # Verify cred_store_state has changed
    if cred_state:
        new_cred_state = dev_manager.ctap2.get_info().get_cred_store_state(token)
        assert new_cred_state != cred_state
        cred_state = new_cred_state

    # Test token before and after reconnect
    for reconnect in (False, True):
        if reconnect:
            dev_manager.reconnect()

        # Use persistent token
        credman = CredentialManagement(dev_manager.ctap2, pin_protocol, token)

        # Test metadata
        assert credman.get_metadata()[1] == 1

        # Test enumerate RPs and creds
        rps = credman.enumerate_rps()
        assert len(rps) == 1
        creds = credman.enumerate_creds(rp_id_hash)
        assert len(creds) == 1

        # Ensure update isn't allowed
        user2 = {"id": b"user_id", "name": "A. User 2"}
        with pytest.raises(CtapError, match="PIN_AUTH_INVALID"):
            credman.update_user_info(cred_id, user2)

        # Ensure delete isn't allowed
        with pytest.raises(CtapError, match="PIN_AUTH_INVALID"):
            credman.delete_cred(cred_id)

        # Ensure cred_store_state is the same
        assert dev_manager.ctap2.get_info().get_cred_store_state(token) == cred_state

    # Compare enc_identifier after reconnect
    assert dev_manager.ctap2.get_info().get_identifier(token) == ident

    # Use new (non-persistent) PIN token
    credman = get_credman(dev_manager.ctap2, pin_protocol)
    credman.delete_cred(cred_id)

    # Verify cred_store_state has changed
    if cred_state:
        new_cred_state = dev_manager.ctap2.get_info().get_cred_store_state(token)
        assert new_cred_state != cred_state
        cred_state = new_cred_state
