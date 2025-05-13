import os

import pytest

from fido2.server import Fido2Server


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if "credBlob" not in dev_manager.info.extensions:
        pytest.skip("CredBlob not supported by authenticator")


def test_read_write(client, ctap2, clear_creds):
    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}

    create_options, state = server.register_begin(
        user,
        resident_key_requirement="required",
        user_verification="required",
    )

    # Create a credential
    blob = os.urandom(32)
    result = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {"credBlob": blob},
        }
    )
    auth_data = server.register_complete(state, result)
    credentials = [auth_data.credential_data]

    assert auth_data.extensions["credBlob"] is True

    request_options, state = server.authenticate_begin(
        credentials, user_verification="required"
    )

    selection = client.get_assertion(
        {
            **request_options["publicKey"],
            "extensions": {"getCredBlob": True},
        }
    )
    result = selection.get_response(0)

    assert result.response.authenticator_data.extensions.get("credBlob") == blob
