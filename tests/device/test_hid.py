def test_ping(device):
    msg1 = b"hello world!"
    msg2 = b"            "
    msg3 = b""
    assert device.ping(msg1) == msg1
    assert device.ping(msg2) == msg2
    assert device.ping(msg3) == msg3
