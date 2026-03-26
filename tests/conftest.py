def pytest_addoption(parser):
    parser.addoption("--reader", action="store")
    parser.addoption("--no-device", action="store_true")
    parser.addoption("--ep-rp-id", action="store")
    parser.addoption("--ccid", action="store_true")
    parser.addoption(
        "--output",
        action="append",
        default=None,
        choices=["cli", "gui"],
        help="Printer output(s) for device tests: cli, gui (may be repeated)",
    )
