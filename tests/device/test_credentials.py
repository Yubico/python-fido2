from fido2.server import Fido2Server


def test_make_assert(client, pin_protocol, algorithm):
    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}

    create_options, state = server.register_begin(user)

    # Create a credential
    result = client.make_credential(
        {
            **create_options["publicKey"],
            "pubKeyCredParams": [algorithm],
        }
    )

    auth_data = server.register_complete(state, result)
    cred = auth_data.credential_data
    assert cred.public_key[3] == algorithm["alg"]
    credentials = [cred]

    # Get assertion
    request_options, state = server.authenticate_begin(credentials)

    # Authenticate the credential
    result = client.get_assertion(request_options.public_key).get_response(0)
    cred_data = server.authenticate_complete(state, credentials, result)
    assert cred_data == cred
