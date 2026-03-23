import os

import pytest

from fido2.client import DefaultClientDataCollector, Fido2Client
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.server import Fido2Server
from fido2.utils import websafe_encode

from . import TEST_PIN, CliInteraction


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if "hmac-secret" not in dev_manager.info.extensions:
        pytest.skip("hmac-secret not supported by authenticator")


def test_prf(client, pin_protocol):
    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}
    uv = "required"

    create_options, state = server.register_begin(user, user_verification=uv)

    # Create a credential
    result = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {"prf": {}},
        }
    )
    assert result.client_extension_results.prf.enabled is True
    assert result.client_extension_results["prf"]["enabled"] is True

    auth_data = server.register_complete(state, result)
    credentials = [auth_data.credential_data]

    # Complete registration
    auth_data = server.register_complete(state, result)
    credential = auth_data.credential_data

    # Generate a salt for PRF:
    salt = websafe_encode(os.urandom(32))

    # Prepare parameters for getAssertion
    credentials = [credential]
    request_options, state = server.authenticate_begin(
        credentials, user_verification=uv
    )

    # Authenticate the credential
    result = client.get_assertion(
        {
            **request_options["publicKey"],
            "extensions": {"prf": {"eval": {"first": salt}}},
        }
    )

    # Only one cred in allowCredentials, only one response.
    response = result.get_response(0)

    output1 = response.client_extension_results.prf.results.first
    assert response.client_extension_results["prf"]["results"][
        "first"
    ] == websafe_encode(output1)

    # Authenticate again, using two salts to generate two secrets.

    # This time we will use evalByCredential, which can be used if there are multiple
    # credentials which use different salts. Here it is not needed, but provided for
    # completeness of the example.

    # Generate a second salt for PRF:
    salt2 = websafe_encode(os.urandom(32))
    # The first salt is reused, which should result in the same secret.

    result = client.get_assertion(
        {
            **request_options["publicKey"],
            "extensions": {
                "prf": {
                    "evalByCredential": {
                        websafe_encode(credential.credential_id): {
                            "first": salt,
                            "second": salt2,
                        }
                    }
                }
            },
        }
    )

    response = result.get_response(0)

    output = response.client_extension_results.prf.results
    assert output.first == output1
    assert output.second != output1
    assert response.client_extension_results["prf"]["results"][
        "second"
    ] == websafe_encode(output.second)


def test_hmac_secret(device, pin_protocol, printer):
    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}
    uv = "required"

    create_options, state = server.register_begin(user, user_verification=uv)

    client = Fido2Client(
        device,
        client_data_collector=DefaultClientDataCollector("https://example.com"),
        user_interaction=CliInteraction(printer, TEST_PIN),
        extensions=[HmacSecretExtension(allow_hmac_secret=True)],
    )

    # Create a credential
    result = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {"hmacCreateSecret": True},
        }
    )
    assert result.client_extension_results.hmac_create_secret is True
    assert result.client_extension_results["hmacCreateSecret"] is True

    # Complete registration
    auth_data = server.register_complete(state, result)
    credentials = [auth_data.credential_data]

    # Generate a salt for HmacSecret:
    salt = os.urandom(32)

    # Prepare parameters for getAssertion
    request_options, state = server.authenticate_begin(
        credentials, user_verification=uv
    )

    result = client.get_assertion(
        {
            **request_options["publicKey"],
            "extensions": {"hmacGetSecret": {"salt1": salt}},
        }
    )
    result = result.get_response(0)

    output1 = result.client_extension_results.hmac_get_secret.output1
    assert result.client_extension_results["hmacGetSecret"][
        "output1"
    ] == websafe_encode(output1)

    salt2 = os.urandom(32)

    result = client.get_assertion(
        {
            **request_options["publicKey"],
            "extensions": {"hmacGetSecret": {"salt1": salt, "salt2": salt2}},
        }
    )
    result = result.get_response(0)

    output = result.client_extension_results.hmac_get_secret
    assert output.output1 == output1
    assert output.output2 != output1


def test_prf_mc(client, pin_protocol, info):
    if "hmac-secret-mc" not in info.extensions:
        pytest.skip("hmac-secret-mc not supported by authenticator")

    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}
    uv = "required"

    create_options, state = server.register_begin(user, user_verification=uv)

    # Generate salts for PRF:
    salt1 = websafe_encode(os.urandom(32))
    salt2 = websafe_encode(os.urandom(32))

    # Create a credential, with salts
    result = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {"prf": {"eval": {"first": salt1, "second": salt2}}},
        }
    )
    auth_data = server.register_complete(state, result)
    credential = auth_data.credential_data

    assert result.client_extension_results.prf.enabled is True
    assert result.client_extension_results["prf"]["enabled"] is True

    output = result.client_extension_results.prf.results
    assert output.first
    assert output.second

    # Prepare parameters for getAssertion
    credentials = [credential]
    request_options, state = server.authenticate_begin(
        credentials, user_verification=uv
    )

    # Authenticate the credential
    result = client.get_assertion(
        {
            **request_options["publicKey"],
            "extensions": {
                "prf": {
                    "evalByCredential": {
                        websafe_encode(credential.credential_id): {
                            "first": salt1,
                            "second": salt2,
                        }
                    }
                }
            },
        }
    )

    response = result.get_response(0)
    assert output == response.client_extension_results.prf.results
