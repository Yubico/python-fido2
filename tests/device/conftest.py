import logging
from dataclasses import replace
from threading import Event, Thread

import pytest

from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client
from fido2.cose import CoseKey
from fido2.ctap2 import Ctap2
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.hid import (
    CAPABILITY,
    CtapHidDevice,
    list_descriptors,
    open_connection,
    open_device,
)

from . import TEST_PIN, CliInteraction, Printer

logger = logging.getLogger(__name__)


class DeviceManager:
    def __init__(self, printer, reader_name):
        self.printer = printer

        self.printer.print(
            "⚠️  Tests will now run against a connected FIDO authenticator. ⚠️ ",
            "",
            "You may be prompted to interact with the authenticator throughout these "
            "tests.",
            "",
            "          ☠️  WARNING! THESE TESTS ARE DESTRUCTIVE! ☠️ ",
            "ANY CREDENTIALS ON THIS AUTHENTICATOR WILL BE PERMANENTLY DELETED!",
        )

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
                self._dev = self._connect_nfc(self._reader, False)
            else:
                pytest.exit(f"No/Multiple NFC readers found matching '{reader_name}'")
        else:
            self._reader = None
            self._dev = self._select()

        if self.has_ctap2():
            info = Ctap2(self.device).info
            if info.transports_for_reset:
                transport = "nfc" if reader_name else "usb"
                self._can_reset = transport in info.transports_for_reset
            else:
                self._can_reset = True
            if info.options.get("clientPin") or info.options.get("uv"):
                self.printer.print(
                    "As a precaution, these tests will not run on an authenticator "
                    "which is configured with any form of UV. Factory reset the "
                    "authenticator prior to running tests against it."
                )
                pytest.exit("Authenticator must be in a newly-reset state!")

            if not self._can_reset:
                self.printer.print(
                    "⚠️  FACTORY RESET NOT ENABLED FOR THIS TRANSPORT! ⚠️ ",
                    "Some tests will be skipped, and the authenticator will be left "
                    "in a state where it will need to be factory reset through another"
                    "transport to be used.",
                )

        self.setup()

    def _select(self):
        event = Event()
        selected = []

        def select(descriptor):
            dev = CtapHidDevice(descriptor, open_connection(descriptor))
            # This client is only used for selection
            client = Fido2Client(
                dev,
                client_data_collector=DefaultClientDataCollector("https://example.com"),
            )
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

        self.printer.touch()

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
        from smartcard.Exceptions import CardConnectionException, NoCardException
        from smartcard.ExclusiveConnectCardConnection import (
            ExclusiveConnectCardConnection,
        )

        from fido2.pcsc import CtapPcscDevice

        logger.debug(f"(Re-)connect over NFC using reader: {reader.name}")
        event = Event()

        def _connect():
            connection = ExclusiveConnectCardConnection(reader.createConnection())
            return CtapPcscDevice(connection, reader.name)

        self.printer.remove(nfc=True)
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
                    self.printer.insert(nfc=True)
                    removed = True

        raise Exception("Failed to (re-)connect to Authenticator")

    @property
    def device(self):
        return self._dev

    def has_ctap2(self):
        return self.device.capabilities & CAPABILITY.CBOR

    @property
    def ctap2(self):
        if self.has_ctap2():
            return Ctap2(self.device)
        pytest.skip("Authenticator does not support CTAP 2")

    @property
    def info(self):
        return self.ctap2.get_info()

    @property
    def on_keepalive(self):
        prompted = [0]

        def on_keepalive(status):
            if status != prompted[0]:
                prompted[0] = status
                if status == 2:
                    self.printer.touch()

        return on_keepalive

    @property
    def client(self):
        return Fido2Client(
            self.device,
            client_data_collector=DefaultClientDataCollector("https://example.com"),
            user_interaction=CliInteraction(self.printer),
        )

    def _reconnect_usb(self):
        event = Event()
        dev_path = self._dev.descriptor.path
        info = Ctap2(self._dev).info
        logger.debug(f"Reconnect over USB: {dev_path}")

        self.printer.remove()
        ds = {d.path for d in list_descriptors()}
        while dev_path in ds:
            event.wait(0.5)
            ds = {d.path for d in list_descriptors()}
        self.printer.insert()
        ds2 = ds
        while True:
            event.wait(0.5)
            ds2 = {d.path for d in list_descriptors()}
            added = ds2 - ds
            if len(added) == 1:
                device = open_device(added.pop())
                info2 = Ctap2(device).info
                assert replace(info, enc_identifier=None) == replace(
                    info2, enc_identifier=None
                )
                return device
            elif len(added) > 1:
                raise ValueError("Multiple Authenticators inserted")

    def reconnect(self):
        if self._reader:
            self._dev.close()
            self._dev.connect()
        else:
            self._dev = self._reconnect_usb()
        return self._dev

    def _factory_reset(self, setup=False):
        if not self._can_reset:
            self.printer.print(
                "☠️  FACTORY RESET CALLED! ☠️ ",
                "",
                "This test should have been marked as requiring reset!",
            )
            pytest.exit("FACTORY RESET CALLED")

        self.printer.print("⚠️  PERFORMING FACTORY RESET! ⚠️ ")

        self.reconnect()

        if self.info.long_touch_for_reset:
            prompted = [0]

            def on_keepalive_reset(status):
                if status != prompted[0]:
                    prompted[0] = status
                    if status == 2:
                        self.printer.print(
                            "👉👉👉 Press the Authenticator button for 10 seconds..."
                        )
                    elif status == 1:
                        self.printer.print("✅ You can now release the button!")

        else:
            on_keepalive_reset = self.on_keepalive

        self.ctap2.reset(on_keepalive=on_keepalive_reset)

        if setup:
            self.setup()

    def setup(self):
        if self.has_ctap2() and ClientPin.is_supported(self.info):
            ClientPin(self.ctap2).set_pin(TEST_PIN)


@pytest.fixture(scope="session")
def printer(request):
    capmanager = request.config.pluginmanager.getplugin("capturemanager")
    return Printer(capmanager)


@pytest.fixture(scope="session", autouse=True)
def dev_manager(pytestconfig, printer):
    if pytestconfig.getoption("no_device"):
        pytest.skip("Skip device tests")

    reader = pytestconfig.getoption("reader")
    manager = DeviceManager(printer, reader)

    yield manager

    # after the test, reset the device, if possible
    if manager._can_reset:
        manager._factory_reset()


@pytest.fixture(scope="session")
def factory_reset(dev_manager):
    if dev_manager._can_reset:
        return dev_manager._factory_reset
    pytest.skip("Requires factory reset")


@pytest.fixture
def device(dev_manager):
    return dev_manager.device


@pytest.fixture
def ctap2(dev_manager):
    return dev_manager.ctap2


@pytest.fixture
def on_keepalive(dev_manager):
    return dev_manager.on_keepalive


@pytest.fixture
def client(dev_manager):
    return dev_manager.client


@pytest.fixture
def info(ctap2):
    return ctap2.get_info()


@pytest.fixture(params=[CoseKey.for_alg(alg) for alg in CoseKey.supported_algorithms()])
def algorithm(request, info):
    alg_cls = request.param
    alg = {"alg": alg_cls.ALGORITHM, "type": "public-key"}
    if alg not in info.algorithms:
        pytest.skip(f"Algorithm {alg_cls.__name__} not supported")
    return alg


@pytest.fixture(params=[PinProtocolV1, PinProtocolV2])
def pin_protocol(request, info):
    proto = request.param
    if proto.VERSION not in info.pin_uv_protocols:
        pytest.skip(f"PIN/UV protocol {proto.VERSION} not supported")

    all_protocols = ClientPin.PROTOCOLS
    # Ensure we always negotiate only the selected protocol
    ClientPin.PROTOCOLS = [proto]
    yield proto()

    ClientPin.PROTOCOLS = all_protocols


@pytest.fixture
def clear_creds(dev_manager):
    # Clears any discoverable credentials after a test
    yield None
    clientpin = ClientPin(dev_manager.ctap2)
    token = clientpin.get_pin_token(TEST_PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    credman = CredentialManagement(dev_manager.ctap2, clientpin.protocol, token)
    for rp in credman.enumerate_rps():
        for cred in credman.enumerate_creds(rp[4]):
            credman.delete_cred(cred[7])
    assert len(credman.enumerate_rps()) == 0
