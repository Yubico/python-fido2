import pytest

from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin

from . import TEST_PIN


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if not ClientPin.is_supported(dev_manager.info):
        pytest.skip("ClientPin not supported by authenticator")


@pytest.fixture
def client_pin(ctap2, pin_protocol):
    return ClientPin(ctap2, pin_protocol)


def test_pin_validation(dev_manager, client_pin):
    assert dev_manager.ctap2.get_info().options["clientPin"] is True
    assert client_pin.get_pin_retries()[0] == 8

    # Wrong PIN decreases the retries remaining
    for retries in range(7, 4, -1):
        # Third attempt uses AUTH_BLOCKED
        with pytest.raises(CtapError, match="PIN_(INVALID|AUTH_BLOCKED)"):
            client_pin.get_pin_token("123456")
        assert client_pin.get_pin_retries()[0] == retries

    # Now soft-locked, does not decrement or unlock with any PIN
    for pin in (TEST_PIN, "123456"):
        with pytest.raises(CtapError, match="PIN_AUTH_BLOCKED"):
            client_pin.get_pin_token(pin)
    assert client_pin.get_pin_retries()[0] == retries

    dev_manager.reconnect()
    client_pin = ClientPin(dev_manager.ctap2, client_pin.protocol)

    # Wrong PIN decreases the retries remaining again
    with pytest.raises(CtapError, match="PIN_INVALID"):
        client_pin.get_pin_token("123456")
    assert client_pin.get_pin_retries()[0] == retries - 1

    # Unlocks with correct PIN
    token = client_pin.get_pin_token(TEST_PIN)
    assert client_pin.get_pin_retries()[0] == 8
    assert token


def test_change_pin(client_pin):
    client_pin.get_pin_token(TEST_PIN)

    new_pin = TEST_PIN[::-1]

    client_pin.change_pin(TEST_PIN, new_pin)
    with pytest.raises(CtapError, match="PIN_INVALID"):
        client_pin.get_pin_token(TEST_PIN)

    client_pin.get_pin_token(new_pin)

    client_pin.change_pin(new_pin, TEST_PIN)
    client_pin.get_pin_token(TEST_PIN)


def test_set_and_reset(dev_manager, client_pin, factory_reset):
    assert dev_manager.ctap2.get_info().options["clientPin"] is True
    assert client_pin.get_pin_retries()[0] == 8

    factory_reset()
    client_pin = ClientPin(dev_manager.ctap2, client_pin.protocol)
    # Factory reset clears the PIN
    assert dev_manager.ctap2.get_info().options["clientPin"] is False
    with pytest.raises(CtapError, match="PIN_NOT_SET"):
        client_pin.get_pin_retries()

    # Setup includes setting the default PIN. More correct would be to just set
    # the PIN ourselves here and test that, but then we need another factory reset
    dev_manager.setup()
    assert dev_manager.ctap2.get_info().options["clientPin"] is True
    assert client_pin.get_pin_retries()[0] == 8
