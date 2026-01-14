import pytest
from fido2.hid import CtapHidDevice


def test_ping(device):
    if not isinstance(device, CtapHidDevice):
        pytest.skip("Device is not a CtapHidDevice")

    msg1 = b"hello world!"
    msg2 = b"            "
    msg3 = b""
    assert device.ping(msg1) == msg1
    assert device.ping(msg2) == msg2
    assert device.ping(msg3) == msg3
