from fido2.client import UserInteraction

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


# Handle user interaction
class CliInteraction(UserInteraction):
    def __init__(self, printer, pin=TEST_PIN):
        self.printer = printer
        self.pin = pin

    def prompt_up(self):
        self.printer.touch()

    def request_pin(self, permissions, rd_id):
        return self.pin

    def request_uv(self, permissions, rd_id):
        self.printer.print("User Verification required.")
        return True
