import os

import pytest

from fido2.client import ClientError
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.server import Fido2Server, to_descriptor

from . import TEST_PIN

rp = {"id": "example.com", "name": "Example RP"}
user = {"id": b"user_id", "name": "A. User"}
server = Fido2Server(rp)


@pytest.fixture(scope="module")
def excluded_match(dev_manager):
    if dev_manager.has_ctap2():
        return "CREDENTIAL_EXCLUDED"
    return "DEVICE_INELIGIBLE"


@pytest.fixture(scope="module")
def credential(dev_manager):
    create_options, state = server.register_begin(user)
    result = dev_manager.client.make_credential(create_options.public_key)
    auth_data = server.register_complete(state, result)
    return auth_data.credential_data


@pytest.fixture(scope="module")
def discoverable_credential(request, dev_manager):
    if not dev_manager.has_ctap2():
        pytest.skip("Authenticator does not support CTAP 2")

    has_credman = CredentialManagement.is_supported(dev_manager.info)
    if not has_credman:
        # Request dynamically since we don't want to skip the test unless needed
        factory_reset = request.getfixturevalue("factory_reset")

    create_options, state = server.register_begin(
        user,
        resident_key_requirement="required",
    )
    result = dev_manager.client.make_credential(create_options.public_key)
    auth_data = server.register_complete(state, result)
    yield auth_data.credential_data

    # Delete credential via credman, or factory reset
    if has_credman:
        client_pin = ClientPin(dev_manager.ctap2)
        token = client_pin.get_pin_token(TEST_PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
        credman = CredentialManagement(dev_manager.ctap2, client_pin.protocol, token)
        cred_id = {"id": auth_data.credential_data.credential_id, "type": "public-key"}
        credman.delete_cred(cred_id)
    else:
        factory_reset(setup=True)


def test_exclude_credentials_single(credential, client, excluded_match):
    create_options, state = server.register_begin(user, [credential])
    with pytest.raises(ClientError, match=excluded_match):
        client.make_credential(create_options.public_key)


def test_exclude_credentials_multiple(credential, client, excluded_match):
    exclude = [{"id": os.urandom(32), "type": "public-key"} for _ in range(5)]
    exclude.insert(3, to_descriptor(credential))
    create_options, state = server.register_begin(user, exclude)
    with pytest.raises(ClientError, match=excluded_match):
        client.make_credential(create_options.public_key)


def test_exclude_credentials_others(credential, client):
    exclude = [{"id": os.urandom(32), "type": "public-key"} for _ in range(5)]
    create_options, state = server.register_begin(user, exclude)
    client.make_credential(create_options.public_key)


def test_allow_credentials_empty(discoverable_credential, client):
    request_options, state = server.authenticate_begin()
    result = client.get_assertion(request_options.public_key).get_response(0)
    server.authenticate_complete(state, [discoverable_credential], result)


def test_allow_credentials_single(credential, client):
    credentials = [credential]
    request_options, state = server.authenticate_begin(credentials)
    result = client.get_assertion(request_options.public_key).get_response(0)
    server.authenticate_complete(state, credentials, result)


def test_allow_credentials_multiple(credential, client):
    credentials = [credential]
    allow = [{"id": os.urandom(32), "type": "public-key"} for _ in range(5)]
    allow.insert(3, to_descriptor(credential))
    request_options, state = server.authenticate_begin(allow)
    result = client.get_assertion(request_options.public_key).get_response(0)
    server.authenticate_complete(state, credentials, result)


def test_allow_credentials_ineligible(credential, client):
    allow = [{"id": os.urandom(32), "type": "public-key"} for _ in range(5)]
    request_options, state = server.authenticate_begin(allow)
    with pytest.raises(ClientError, match="DEVICE_INELIGIBLE"):
        client.get_assertion(request_options.public_key)
