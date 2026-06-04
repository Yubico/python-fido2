import logging
import time
from threading import Timer

import urllib.request

from fido2.client import UserInteraction

logger = logging.getLogger(__name__)

TEST_PIN = "a1b2c3d4"


class Printer:
    def __init__(self, capmanager):
        self.capmanager = capmanager

    def print(self, *messages):
        with self.capmanager.global_and_fixture_disabled():
            print("")
            for m in messages:
                print(m)

    def touch(self):
        self.print("👉 Touch the Authenticator")

    def insert(self, nfc=False):
        self.print(
            "♻️  "
            + (
                "Place the Authenticator on the NFC reader"
                if nfc
                else "Connect the Authenticator"
            )
        )

    def remove(self, nfc=False):
        self.print(
            "🚫 "
            + (
                "Remove the Authenticator from the NFC reader"
                if nfc
                else "Disconnect the Authenticator"
            )
        )


class PicoController:
    def __init__(self, base_url, port, printer):
        self.base_url = base_url.rstrip("/")
        self.port = port
        self.printer = printer
        self._touch_timer = None
        self._preflight()

    def _preflight(self):
        import pytest

        try:
            self._request("/")
        except Exception as e:
            pytest.exit(f"Pico controller not reachable at {self.base_url}: {e}")

    def _request(self, path):
        url = f"{self.base_url}{path}"
        logger.debug(f"Pico request: {url}")
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read()

    def print(self, *messages):
        self.printer.print(*messages)

    def touch(self):
        if self._touch_timer:
            self._touch_timer.cancel()
            self._touch_timer = None
        self._request(f"/usb{self.port}/touch/off")
        time.sleep(0.1)
        self._request(f"/usb{self.port}/touch/on")
        self._touch_timer = Timer(10.0, self._touch_off)
        self._touch_timer.daemon = True
        self._touch_timer.start()

    def _touch_off(self):
        self._touch_timer = None
        try:
            self._request(f"/usb{self.port}/touch/off")
        except Exception:
            pass

    def insert(self, nfc=False):
        self._request(f"/usb{self.port}/power/on")
        time.sleep(1)

    def remove(self, nfc=False):
        self._touch_off()
        self._request(f"/usb{self.port}/power/off")
        time.sleep(1)


# Handle user interaction
class CliInteraction(UserInteraction):
    def __init__(self, printer, pin=TEST_PIN):
        self.printer = printer
        self.pin = pin

    def prompt_up(self):
        self.printer.touch()

    def request_pin(self, permissions, rp_id):
        return self.pin

    def request_uv(self, permissions, rp_id):
        self.printer.print("User Verification required.")
        return True
