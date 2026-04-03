import time
from threading import Event

import pytest
from fido2.ctap import CtapError
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


def test_selection_cancel(ctap2, info):
    """Test that cancelling a selection command returns promptly."""
    if "FIDO_2_1" not in info.versions:
        pytest.skip("authenticatorSelection requires CTAP 2.1")

    event = Event()
    event.set()  # Cancel immediately

    start = time.monotonic()
    with pytest.raises(CtapError) as exc_info:
        ctap2.selection(event=event)
    elapsed = time.monotonic() - start

    assert exc_info.value.code == CtapError.ERR.KEEPALIVE_CANCEL
    assert elapsed < 5, f"Cancel took too long: {elapsed:.1f}s (expected < 5s)"
