from fido2.client import UserInteraction


TEST_PIN = "a1b2c3d4"


class Printer:
    def __init__(self, capmanager):
        self.capmanager = capmanager

    def print(self, *messages):
        with self.capmanager.global_and_fixture_disabled():
            for m in messages:
                print(m)


# Handle user interaction
class CliInteraction(UserInteraction):
    def __init__(self, printer, pin=TEST_PIN):
        self.printer = printer
        self.pin = pin

    def prompt_up(self):
        self.printer.print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return self.pin

    def request_uv(self, permissions, rd_id):
        self.printer.print("\nUser Verification required.")
        return True
