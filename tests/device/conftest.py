from fido2.hid import CtapHidDevice, list_descriptors, open_connection, open_device
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.client import Fido2Client, ClientError, UserInteraction

from . import TEST_PIN

from threading import Thread, Event

import pytest
import logging

logger = logging.getLogger(__name__)


# Handle user interaction
class CliInteraction(UserInteraction):
    def __init__(self, capmanager, pin):
        self.capmanager = capmanager
        self.pin = pin

    def prompt_up(self):
        with self.capmanager.global_and_fixture_disabled():
            print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return self.pin

    def request_uv(self, permissions, rd_id):
        with self.capmanager.global_and_fixture_disabled():
            print("\nUser Verification required.")
        return True


class DeviceManager:
    def __init__(self, capmanager, reader_name):
        self.capmanager = capmanager

        with self.capmanager.global_and_fixture_disabled():
            print("")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("Tests will now run against a connected FIDO authenticator.")
            print("")
            print("THESE TESTS ARE DESTRUCTIVE!")
            print("ANY CREDENTIALS ON THIS AUTHENTICATOR WILL BE PERMANENTLY DELETED!")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        if reader_name:
            try:
                from fido2.pcsc import _list_readers
            except ImportError:
                pytest.exit("pyscard not installed, install package with 'pcsc' extra")

            readers = [
                r for r in _list_readers() if reader_name.lower() in r.name.lower()
            ]
            if len(readers) == 1:
                self._reader = readers[0]
                with self.capmanager.global_and_fixture_disabled():
                    self._dev = self._connect_nfc(self._reader, False)
            else:
                pytest.exit(f"No/Multiple NFC readers found matching '{reader_name}'")
        else:
            self._reader = None
            self._dev = self._select()

        options = self.ctap2.info.options
        if options.get("clientPin") or options.get("uv"):
            pytest.exit("Authenticator must be in a newly-reset state!")

        self.setup()

    def _select(self):
        event = Event()
        selected = []

        def select(descriptor):
            dev = CtapHidDevice(descriptor, open_connection(descriptor))
            # This client is only used for selection
            client = Fido2Client(dev, "https://example.com")
            try:
                while not event.is_set():
                    try:
                        client.selection(event)
                        selected.append(dev)
                        event.set()
                        break
                    except ClientError as e:
                        if e.code != ClientError.ERR.TIMEOUT:
                            raise
            except Exception:
                logger.debug(
                    f"Authenticator selection failed for {descriptor.path}",
                    exc_info=True,
                )

        with self.capmanager.global_and_fixture_disabled():
            print("Insert and touch the authenticator to test...")

        descriptors: set[str | bytes] = set()
        threads: list[Thread] = []
        try:
            while not event.wait(0.1):
                if event.is_set():
                    break
                removed = set(descriptors)
                for d in list_descriptors():
                    if d.path not in descriptors:
                        descriptors.add(d.path)
                        t = Thread(target=select, args=(d,))
                        threads.append(t)
                        t.start()
                    else:
                        removed.remove(d.path)
                descriptors -= removed
        finally:
            event.set()

        for t in threads:
            # wait for child threads to finish
            t.join()

        if selected:
            logger.debug("Authenticator selected")
            return selected[0]
        else:
            pytest.exit("No Authenticator selected")

    def _connect_nfc(self, reader, reconnect=True):
        from fido2.pcsc import CtapPcscDevice
        from smartcard.Exceptions import NoCardException, CardConnectionException
        from smartcard.ExclusiveConnectCardConnection import (
            ExclusiveConnectCardConnection,
        )

        logger.debug(f"(Re-)connect over NFC using reader: {reader.name}")
        event = Event()

        def _connect():
            connection = ExclusiveConnectCardConnection(reader.createConnection())
            return CtapPcscDevice(connection, reader.name)

        print("Remove Authenticator from the NFC reader now...")
        removed = False
        while not event.wait(0.5):
            try:
                dev = _connect()
                if removed:
                    dev.close()
                    event.wait(1.0)  # Wait for the device to settle
                    return _connect()
                dev.close()
            except CardConnectionException:
                pass  # Expected, ignore
            except (NoCardException, KeyError):
                if not removed:
                    print("Place Authenticator on the NFC reader now...")
                    removed = True

        raise Exception("Failed to (re-)connect to Authenticator")

    @property
    def device(self):
        return self._dev

    @property
    def ctap2(self):
        return Ctap2(self.device)

    @property
    def info(self):
        return self.ctap2.get_info()

    @property
    def client(self):
        return Fido2Client(
            self.device,
            "https://example.com",
            user_interaction=CliInteraction(self.capmanager, TEST_PIN),
        )

    def _reconnect_usb(self):
        event = Event()
        dev_path = self._dev.descriptor.path
        info = Ctap2(self._dev).info
        logger.debug(f"Reconnect over USB: {dev_path}")

        print("")
        print("Disconnect the Authenticator now...")
        ds = {d.path for d in list_descriptors()}
        while dev_path in ds:
            event.wait(0.5)
            ds = {d.path for d in list_descriptors()}
        print("Re-insert the Authenticator now...")
        ds2 = ds
        while True:
            event.wait(0.5)
            ds2 = {d.path for d in list_descriptors()}
            added = ds2 - ds
            if len(added) == 1:
                device = open_device(added.pop())
                info2 = Ctap2(device).info
                assert info == info2
                return device
            elif len(added) > 1:
                raise ValueError("Multiple Authenticators inserted")

    def reconnect(self):
        if self._reader:
            self._dev.close()
            self._dev.connect()
        else:
            with self.capmanager.global_and_fixture_disabled():
                self._dev = self._reconnect_usb()
        return self._dev

    def factory_reset(self, setup=False):
        with self.capmanager.global_and_fixture_disabled():
            print("\nPERFORMING FACTORY RESET!")

        self.reconnect()

        prompted = []

        def on_keepalive(status):
            if not prompted and status == 2:
                prompted.append(True)
                with self.capmanager.global_and_fixture_disabled():
                    print("Touch the Authenticator now...")

        self.ctap2.reset(on_keepalive=on_keepalive)

        if setup:
            self.setup()

    def setup(self):
        if ClientPin.is_supported(self.info):
            ClientPin(self.ctap2).set_pin(TEST_PIN)


@pytest.fixture(scope="session", autouse=True)
def dev_manager(pytestconfig, request):
    if pytestconfig.getoption("no_device"):
        pytest.skip("Skip device tests")

    reader = pytestconfig.getoption("reader")
    capmanager = request.config.pluginmanager.getplugin("capturemanager")
    manager = DeviceManager(capmanager, reader)

    yield manager

    # after the test, reset the device
    manager.factory_reset()


@pytest.fixture
def device(dev_manager):
    return dev_manager.device


@pytest.fixture
def ctap2(dev_manager):
    return dev_manager.ctap2


@pytest.fixture
def client(dev_manager):
    return dev_manager.client


@pytest.fixture
def info(ctap2):
    return ctap2.get_info()
