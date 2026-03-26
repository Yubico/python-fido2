import json
import multiprocessing
import os
import signal
from threading import Thread

from fido2.client import UserInteraction

TEST_PIN = "a1b2c3d4"


class Printer:
    def print(self, *messages):
        pass

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

    def close(self):
        pass


class CliPrinter(Printer):
    def __init__(self, capmanager):
        self.capmanager = capmanager

    def print(self, *messages):
        with self.capmanager.global_and_fixture_disabled():
            print("")
            for m in messages:
                print(m)


_EMOJI_MAP = {
    "👉": "\u25b6",  # ▶
    "🚫": "\u2718",  # ✘
    "♻️": "\u21bb",  # ↻
    "⚠️": "\u26a0",  # ⚠
    "☠️": "\u2620",  # ☠
    "✅": "\u2714",  # ✔
}


def _replace_emoji(text):
    for emoji, replacement in _EMOJI_MAP.items():
        text = text.replace(emoji, replacement)
    # Strip variation selectors and other non-displayable characters
    return text.translate({0xFE0E: None, 0xFE0F: None, 0x200D: None})


def _gui_process(msg_queue, ready_event):
    """Run the tkinter GUI in a separate process."""
    import tkinter as tk
    import tkinter.font as tkfont

    root = tk.Tk()
    root.title("FIDO2 Device Tests")
    root.geometry("600x400")
    root.configure(bg="#1e1e1e")

    header = tk.Label(
        root,
        text="FIDO2 Device Test Runner",
        bg="#1e1e1e",
        fg="#cccccc",
        font=("sans-serif", 14, "bold"),
        pady=10,
    )
    header.pack(fill=tk.X)

    separator = tk.Frame(root, height=1, bg="#444444")
    separator.pack(fill=tk.X, padx=10)

    frame = tk.Frame(root, bg="#1e1e1e")
    frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

    label_font = tkfont.Font(family="sans-serif", size=11)
    label_font_bold = tkfont.Font(family="sans-serif", size=13, weight="bold")

    labels = []

    def poll_queue():
        try:
            raw = msg_queue.get_nowait()
        except Exception:
            root.after(100, poll_queue)
            return
        if raw is None:
            root.destroy()
            return
        messages = json.loads(raw)
        for label in labels:
            label.configure(fg="#aaaaaa", font=label_font)
        for msg in messages:
            if not msg:
                continue
            label = tk.Label(
                frame,
                text=_replace_emoji(msg),
                bg="#1e1e1e",
                fg="#ffffff",
                font=label_font_bold,
                anchor=tk.W,
                wraplength=560,
                justify=tk.LEFT,
                pady=3,
            )
            label.pack(fill=tk.X)
            labels.append(label)
        root.after(500 if not msg_queue.empty() else 100, poll_queue)

    def on_ready():
        ready_event.set()
        poll_queue()

    root.after(0, on_ready)
    root.mainloop()


class GuiPrinter(Printer):
    def __init__(self):
        ctx = multiprocessing.get_context("spawn")
        self._msg_queue = ctx.Queue()
        self._ready = ctx.Event()
        self._process = ctx.Process(
            target=_gui_process,
            args=(self._msg_queue, self._ready),
            daemon=True,
        )
        self._process.start()
        self._ready.wait()
        self._closing = False

        # Monitor thread: abort tests if the GUI window is closed
        monitor = Thread(target=self._monitor, daemon=True)
        monitor.start()

    def _monitor(self):
        self._process.join()
        if not self._closing:
            os.kill(os.getpid(), signal.SIGINT)

    def print(self, *messages):
        self._msg_queue.put(json.dumps(messages))

    def close(self):
        self._closing = True
        if self._process.is_alive():
            self._msg_queue.put(None)
            self._process.join(timeout=2)
        if self._process.is_alive():
            self._process.kill()


class CompositePrinter(Printer):
    def __init__(self, printers):
        self._printers = printers

    def print(self, *messages):
        for p in self._printers:
            p.print(*messages)

    def close(self):
        for p in self._printers:
            p.close()


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
