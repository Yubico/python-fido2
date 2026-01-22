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

    # Create a credential
    blob = os.urandom(32)
    create_options, state = server.register_begin(
        user,
        authenticator_selection={
            "userVerification": "required",
            "residentKey": "required",
        },
        extensions={"credBlob": blob},
    )
    result = client.make_credential(create_options.public_key)
    auth_data = server.register_complete(state, result)
    credentials = [auth_data.credential_data]

    assert auth_data.extensions["credBlob"] is True

    request_options, state = server.authenticate_begin(
        credentials,
        user_verification="required",
        extensions={"getCredBlob": True},
    )

    selection = client.get_assertion(request_options.public_key)
    result = selection.get_response(0)

    assert result.response.authenticator_data.extensions.get("credBlob") == blob
