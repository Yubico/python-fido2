def pytest_addoption(parser):
    parser.addoption("--reader", action="store")
    parser.addoption("--no-device", action="store_true")
