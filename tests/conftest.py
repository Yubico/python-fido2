def pytest_addoption(parser):
    parser.addoption("--reader", action="store")
    parser.addoption("--no-device", action="store_true")
    parser.addoption("--ep-rp-id", action="store")
    parser.addoption("--ccid", action="store_true")
    parser.addoption("--controller", action="store")
    parser.addoption("--pico-port", action="store", type=int, default=6)
