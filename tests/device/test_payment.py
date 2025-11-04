import pytest

from fido2.client import Fido2Client
from fido2.ctap2.extensions import (
    PaymentCredentialInstrument,
    PaymentCurrencyAmount,
    ThirdPartyPaymentExtension,
)
from fido2.payment import (
    CollectedClientAdditionalPaymentData,
    PaymentClientDataCollector,
)
from fido2.server import Fido2Server
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin

from . import TEST_PIN, CliInteraction


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if "thirdPartyPayment" not in dev_manager.info.extensions:
        pytest.skip("thirdPartyPayment not supported by authenticator")


def test_payment_extension(device, printer, ctap2, pin_protocol):
    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}

    # Prepare parameters for makeCredential
    create_options, state = server.register_begin(
        user,
        resident_key_requirement="required",
        user_verification="required",
        authenticator_attachment="cross-platform",
    )

    client = Fido2Client(
        device,
        client_data_collector=PaymentClientDataCollector("https://example.com"),
        user_interaction=CliInteraction(printer, TEST_PIN),
        extensions=[ThirdPartyPaymentExtension()],
    )

    # Create a credential
    result = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {"payment": {"isPayment": True}},
        }
    )

    # Complete registration
    auth_data = server.register_complete(state, result)
    credentials = [auth_data.credential_data]

    print("Payment credential created!")

    # Test flag in Credential Management
    token = ClientPin(ctap2, pin_protocol).get_pin_token(
        TEST_PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT
    )
    cm = CredentialManagement(ctap2, pin_protocol, token)
    rps = cm.enumerate_rps()
    rp_id_hash = rps[0][4]
    creds = cm.enumerate_creds(rp_id_hash)
    assert creds[0][CredentialManagement.RESULT.THIRD_PARTY_PAYMENT] == True

    # Prepare parameters for getAssertion
    request_options, state = server.authenticate_begin(
        credentials, user_verification="required"
    )

    # Prepare payment options
    payment = CollectedClientAdditionalPaymentData(
        rp_id="example.com",
        top_origin="https://top.example.com",
        payee_name="Mr. Payee",
        payee_origin="https://payee.example.com",
        total=PaymentCurrencyAmount(
            currency="USD",
            value="1.00",
        ),
        instrument=PaymentCredentialInstrument(
            display_name="My Payment",
            icon="https://example.com/icon.png",
        ),
    )

    # Authenticate the credential
    result = client.get_assertion(
        {
            **request_options["publicKey"],
            "extensions": {
                "payment": dict(payment, isPayment=True),
            },
        }
    )

    # Only one cred in allowCredentials, only one response.
    result = result.get_response(0)

    # Verify that the key includes the payment extension
    assert result.response.authenticator_data.extensions["thirdPartyPayment"] is True

    # Verify that the client has added the payment data
    assert result.response.client_data.type == "payment.get"
    assert result.response.client_data.payment == payment
