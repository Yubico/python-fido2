import pytest

from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client
from fido2.ctap import CtapError
from fido2.ctap2.config import Config
from fido2.ctap2.pin import ClientPin
from fido2.server import Fido2Server

from . import TEST_PIN, CliInteraction


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if not Config.is_supported(dev_manager.info):
        pytest.skip("Config not supported by authenticator")


@pytest.fixture
def client_pin(ctap2, pin_protocol):
    return ClientPin(ctap2, pin_protocol)


def get_config(
    ctap2,
    pin_protocol,
    pin=TEST_PIN,
    permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG,
):
    token = ClientPin(ctap2, pin_protocol).get_pin_token(pin, permissions)
    return Config(ctap2, pin_protocol, token)


def test_always_uv(ctap2, pin_protocol, device, printer):
    always_uv = ctap2.info.options.get("alwaysUv")
    if always_uv is None:
        pytest.skip("AlwaysUv not supported")

    # Toggle on, if off
    if not always_uv:
        config = get_config(ctap2, pin_protocol)
        config.toggle_always_uv()

    assert ctap2.get_info().options["alwaysUv"] is True

    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}

    create_options, state = server.register_begin(user, user_verification="discouraged")

    # Create a credential
    client = Fido2Client(
        device,
        client_data_collector=DefaultClientDataCollector("https://example.com"),
        user_interaction=CliInteraction(printer, "WrongPin"),
    )

    # Should require PIN due to alwaysUV and fail
    with pytest.raises(ClientError, match="PIN_INVALID"):
        client.make_credential(create_options.public_key)

    # Toggle back off, if toggled on
    if not always_uv:
        config = get_config(ctap2, pin_protocol)
        config.toggle_always_uv()
        assert ctap2.get_info().options["alwaysUv"] is False

        # Now create the credential without requiring auth
        client.make_credential(create_options.public_key)


def test_force_pin_change(ctap2, pin_protocol, client_pin):
    assert ctap2.get_info().force_pin_change is False
    client_pin.get_pin_token(TEST_PIN)

    config = get_config(ctap2, pin_protocol)
    config.set_min_pin_length(force_change_pin=True)
    assert ctap2.get_info().force_pin_change is True

    with pytest.raises(CtapError, match="PIN_INVALID"):
        client_pin.get_pin_token(TEST_PIN)

    pin = TEST_PIN[::-1]
    client_pin.change_pin(TEST_PIN, pin)
    client_pin.change_pin(pin, TEST_PIN)
    client_pin.get_pin_token(TEST_PIN)


def test_min_pin_length(
    dev_manager, ctap2, pin_protocol, client_pin, printer, factory_reset
):
    config = get_config(ctap2, pin_protocol)

    orig_len = ctap2.info.min_pin_length

    config.set_min_pin_length(min_pin_length=orig_len + 2)

    pin = TEST_PIN * 4

    # Too short
    with pytest.raises(CtapError, match="PIN_POLICY_VIOLATION"):
        client_pin.change_pin(TEST_PIN, pin[:orig_len])

    # Just long enough
    client_pin.change_pin(TEST_PIN, pin[: orig_len + 2])

    # Even longer
    client_pin.change_pin(pin[: orig_len + 2], pin[: orig_len + 4])

    config = get_config(ctap2, pin_protocol, pin=pin[: orig_len + 4])

    # Cannot shorten min pin length
    with pytest.raises(CtapError, match="PIN_POLICY_VIOLATION"):
        config.set_min_pin_length(min_pin_length=orig_len)

    config.set_min_pin_length(min_pin_length=orig_len + 6)

    # Current PIN is too short
    assert ctap2.get_info().force_pin_change is True

    client_pin.change_pin(pin[: orig_len + 4], pin[: orig_len + 6])
    assert ctap2.get_info().force_pin_change is False

    # Test minPinLength extension
    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}

    create_options, state = server.register_begin(user, user_verification="discouraged")

    if "setMinPINLength" in ctap2.info.options:
        config = get_config(ctap2, pin_protocol, pin=pin[: orig_len + 6])
        config.set_min_pin_length(rp_ids=[rp["id"]])
        client = Fido2Client(
            dev_manager.device,
            client_data_collector=DefaultClientDataCollector("https://example.com"),
            user_interaction=CliInteraction(printer, pin[: orig_len + 6]),
        )

        result = client.make_credential(
            {
                **create_options["publicKey"],
                "extensions": {"minPinLength": True},
            }
        )
        auth_data = server.register_complete(state, result)
        assert auth_data.extensions["minPinLength"] == orig_len + 6

    # Restore original config
    factory_reset(setup=True)
    assert dev_manager.info.min_pin_length == orig_len


@pytest.fixture(scope="module")
def enable_ep(dev_manager, factory_reset):
    if "ep" not in dev_manager.info.options:
        pytest.skip("Enterprise Attestation not supported")

    assert dev_manager.info.options["ep"] is False

    # Enable EP
    pin_protocol = ClientPin(dev_manager.ctap2).protocol
    config = get_config(dev_manager.ctap2, pin_protocol)
    config.enable_enterprise_attestation()
    assert dev_manager.info.options["ep"] is True

    yield None

    # Restore original config
    factory_reset(setup=True)
    assert dev_manager.info.options["ep"] is False


@pytest.fixture(scope="module")
def att_cert(dev_manager):
    rp = {"id": "example.com", "name": "Example RP"}
    user = {"id": b"user_id", "name": "A. User"}

    server = Fido2Server(rp, attestation="direct")
    create_options, state = server.register_begin(user)
    result = dev_manager.client.make_credential(create_options.public_key)
    return result.response.attestation_object.att_stmt["x5c"][0]


def test_ep_platform(client, enable_ep, att_cert):
    rp = {"id": "example.com", "name": "Example RP"}
    user = {"id": b"user_id", "name": "A. User"}

    server = Fido2Server(rp, attestation="enterprise")
    create_options, state = server.register_begin(user)

    client._enterprise_rpid_list = [rp["id"]]
    result = client.make_credential(create_options.public_key)
    cert = result.response.attestation_object.att_stmt["x5c"][0]

    assert att_cert != cert


def test_ep_vendor(pytestconfig, device, printer, enable_ep, att_cert):
    ep_rp_id = pytestconfig.getoption("ep_rp_id")
    if not ep_rp_id:
        pytest.skip("No RP ID provided with --ep-rp-id")

    rp = {"id": ep_rp_id, "name": "Example RP"}
    user = {"id": b"user_id", "name": "A. User"}

    server = Fido2Server(rp, attestation="enterprise")
    create_options, state = server.register_begin(user)

    client = Fido2Client(
        device,
        client_data_collector=DefaultClientDataCollector(f"https://{ep_rp_id}"),
        user_interaction=CliInteraction(printer),
    )

    result = client.make_credential(create_options.public_key)
    cert = result.response.attestation_object.att_stmt["x5c"][0]

    assert att_cert != cert
